/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

//! How a `download_file` whose checksum does not give the file's CAS digest gets its content.
//!
//! The CAS names a blob by its sha256 and size. A `download_file` declared only by, say, a
//! `sha512` does not say what those are until the file has been read, so the action cannot ask the
//! CAS for the file the way it does when `sha256` and a size are known. If remote execution is
//! configured, a Remote Asset server is asked first which CAS blob is known under the file's
//! checksum. A hit gives the sha256 and size, and the normal CAS path runs, so no bytes move. On a
//! miss (or any error) the file is downloaded and checked against its checksums, and then, so the
//! next client does not have to download it, it is uploaded to the CAS and the server is told which
//! blob it is.
//!
//! Remote Asset is an optimisation and never what breaks or stalls a build: every call has a
//! deadline, the lookup is a single attempt, a server that answers `UNIMPLEMENTED` is not asked
//! again, and a failure of any step is reported as a warning and falls back to the download.
//! The URL is sent to the server (and so may reach its logs), so a URL that carries credentials
//! leaks them to it.

use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use buck2_common::cas_digest::CasDigestConfig;
use buck2_common::cas_digest::DigestAlgorithm;
use buck2_common::file_ops::metadata::FileDigest;
use buck2_core::soft_error;
use buck2_error::ErrorTag;
use buck2_error::buck2_error;
use buck2_execute::materialize::http::ChecksumKey;

/// What the download of such a file needs from the Remote Asset server and the CAS behind it.
/// All digests are sha256.
#[async_trait]
pub(crate) trait ChecksumAliases: Send + Sync {
    /// The blob the server knows under the hash `key` at `url`, if any. `Ok(None)` is a miss.
    ///
    /// Trust: the hash in `key` is not checked on this path. A hit is trusted to the extent the
    /// Remote Asset server and the CAS are trusted (the same endpoint already controls CAS
    /// contents and action outputs), and the server is expected to have verified the hash before it
    /// recorded the alias. A hit can only name a blob that exists in the CAS, and the caller
    /// rechecks presence through `declare_from_cas`. The checksums are verified client-side only when
    /// the file is downloaded over HTTP. A stricter option would be a config key that disables alias
    /// lookups.
    async fn fetch(
        &self,
        url: &str,
        key: ChecksumKey<'_>,
    ) -> buck2_error::Result<Option<FileDigest>>;

    /// Puts the downloaded file, whose digest is `digest`, in the CAS. Returns once the server has
    /// acknowledged it.
    async fn upload(&self, digest: &FileDigest) -> buck2_error::Result<()>;

    /// Records that the blob `digest`, which the server must already hold, is the content behind
    /// the hash `key` at `url`.
    async fn push(
        &self,
        url: &str,
        key: ChecksumKey<'_>,
        digest: &FileDigest,
    ) -> buck2_error::Result<()>;
}

/// Whether Remote Asset is used at all. It needs a CAS to ask, and a CAS keyed by sha256: the
/// digests a Remote Asset server hands back are asked for as sha256, so under another function
/// they would name nothing.
pub(crate) fn aliases_usable(cas_configured: bool, digest_config: CasDigestConfig) -> bool {
    cas_configured && digest_config.preferred_algorithm() == DigestAlgorithm::Sha256
}

#[derive(Debug)]
pub(crate) enum Resolved<T> {
    /// A Remote Asset server named the content and the CAS has it; nothing was downloaded.
    FromCas(T),
    /// The content was downloaded from the URL.
    Downloaded(T),
}

/// How long each Remote Asset step may take before it is given up on. A step that times out
/// behaves like any other failure of it: a miss for the lookup, a logged and ignored failure for
/// the upload and the push. None of them is ever allowed to stall a build.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadlines {
    pub lookup: Duration,
    pub upload: Duration,
    pub push: Duration,
}

/// The lookup and the push are small requests, so ten seconds is generous. The upload moves the
/// whole file, so its bound is a stall detector rather than a speed requirement.
pub(crate) const DEADLINES: Deadlines = Deadlines {
    lookup: Duration::from_secs(10),
    upload: Duration::from_secs(300),
    push: Duration::from_secs(10),
};

/// The Remote Asset server to use for a download, and what is known about it.
pub(crate) struct RemoteAsset<'a> {
    pub aliases: &'a dyn ChecksumAliases,
    /// Set once the server has answered `UNIMPLEMENTED`. Whoever owns the flag decides how long
    /// that is remembered; the daemon keeps one for its whole life, so a server without Remote
    /// Asset is asked once, warned about once, and not asked again by any later download.
    pub unimplemented: &'a AtomicBool,
    pub deadlines: Deadlines,
}

impl RemoteAsset<'_> {
    fn usable(&self) -> bool {
        !self.unimplemented.load(Ordering::Relaxed)
    }

    /// Reports a step that did not work out. Never fails the build. `UNIMPLEMENTED` is remembered
    /// and reported once; anything else is reported (at most a few times per build, see
    /// `soft_error!`) so a server that does not work is not silently turned into an origin fetch
    /// of every file.
    fn degraded(&self, category: &str, what: &str, url: &str, error: buck2_error::Error) {
        if error.has_tag(ErrorTag::ReUnimplemented) {
            if !self.unimplemented.swap(true, Ordering::Relaxed) {
                soft_error!(
                    "download_file_remote_asset_unimplemented",
                    error.context(
                        "The Remote Asset server does not implement the Remote Asset API; \
                         `download_file` will download from the URL and not ask it again"
                    ),
                    quiet: false
                )
                .ok();
            }
            return;
        }
        soft_error!(
            category,
            error.context(format!("{what} `{url}`; continuing without it")),
            quiet: false
        )
        .ok();
    }

    /// Runs one step under its deadline.
    async fn within<T>(
        &self,
        deadline: Duration,
        step: impl Future<Output = buck2_error::Result<T>>,
    ) -> buck2_error::Result<T> {
        match tokio::time::timeout(deadline, step).await {
            Ok(result) => result,
            Err(_) => Err(buck2_error!(
                ErrorTag::ReDeadlineExceeded,
                "no answer within {:?}",
                deadline
            )),
        }
    }
}

/// Gets the content of the file at `url`, which is known by the hash `key`.
///
/// `expected_size` is `size_bytes` if the rule author gave one. A hit that names a blob of another
/// size is not trusted: it is reported and treated as a miss, and the download that follows fails
/// on the same size check as any other.
///
/// `from_cas` turns the digest a hit names into the action's value, or says the CAS cannot serve
/// it after all (`None`). `download` downloads and verifies the file and returns its value and
/// digest. With `remote` `None` (no remote execution) nothing but `download` runs.
///
/// Remote Asset never fails the build: the lookup is one attempt under a deadline, and whatever
/// goes wrong with it, including a hit that `from_cas` then cannot serve, falls back to the
/// download. Telling the server about the blob is best effort in the same way.
pub(crate) async fn resolve<T, FromCasFut, DownloadFut>(
    remote: Option<&RemoteAsset<'_>>,
    url: &str,
    key: ChecksumKey<'_>,
    expected_size: Option<u64>,
    from_cas: impl FnOnce(FileDigest) -> FromCasFut,
    download: impl FnOnce() -> DownloadFut,
) -> buck2_error::Result<Resolved<T>>
where
    FromCasFut: Future<Output = buck2_error::Result<Option<T>>> + Send,
    DownloadFut: Future<Output = buck2_error::Result<(T, FileDigest)>> + Send,
    T: Send,
{
    let Some(remote) = remote else {
        return Ok(Resolved::Downloaded(download().await?.0));
    };

    if remote.usable() {
        let lookup = remote
            .within(remote.deadlines.lookup, remote.aliases.fetch(url, key))
            .await;
        match lookup {
            Ok(Some(digest)) if expected_size.is_some_and(|size| size != digest.size()) => {
                remote.degraded(
                    "download_file_remote_asset_size_mismatch",
                    &format!(
                        "The Remote Asset server named a blob of {} bytes, but `size_bytes` is {}, for",
                        digest.size(),
                        expected_size.unwrap_or_default(),
                    ),
                    url,
                    buck2_error!(
                        ErrorTag::DownloadSizeMismatch,
                        "blob size does not match `size_bytes`"
                    ),
                );
            }
            Ok(Some(digest)) => match from_cas(digest).await {
                Ok(Some(value)) => return Ok(Resolved::FromCas(value)),
                Ok(None) => {}
                Err(e) => remote.degraded(
                    "download_file_remote_asset_cas_unavailable",
                    "The Remote Asset server named a blob the CAS could not serve for",
                    url,
                    e,
                ),
            },
            Ok(None) => {}
            Err(e) => remote.degraded(
                "download_file_remote_asset_lookup_failed",
                "Remote Asset lookup failed for",
                url,
                e,
            ),
        }
    }

    let (value, digest) = download().await?;

    // The server refuses an alias for a blob it does not hold, so the upload has to be
    // acknowledged before the push is sent. (The lookup may just have learned the server has no
    // Remote Asset, in which case there is nothing to tell it.)
    if remote.usable() {
        match remote
            .within(remote.deadlines.upload, remote.aliases.upload(&digest))
            .await
        {
            Ok(()) => {
                if remote.usable() {
                    if let Err(e) = remote
                        .within(
                            remote.deadlines.push,
                            remote.aliases.push(url, key, &digest),
                        )
                        .await
                    {
                        remote.degraded(
                            "download_file_remote_asset_push_failed",
                            "Could not record with the Remote Asset server",
                            url,
                            e,
                        );
                    }
                }
            }
            Err(e) => remote.degraded(
                "download_file_remote_asset_upload_failed",
                "Could not upload to the CAS",
                url,
                e,
            ),
        }
    }

    Ok(Resolved::Downloaded(value))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use buck2_common::cas_digest::testing;
    use buck2_core::fs::project::ProjectRootTemp;
    use buck2_core::fs::project_rel_path::ProjectRelativePath;
    use buck2_execute::digest_config::DigestConfig;
    use buck2_execute::materialize::http::Checksum;
    use buck2_execute::materialize::http::http_download;
    use buck2_execute::re::error::test_re_error;
    use buck2_http::HttpClient;
    use buck2_http::HttpClientBuilder;
    use remote_execution::TCode;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    use super::*;

    const BODY: &[u8] = b"foobar";
    // sha512 of "foobar", and of "foobaz": a download with one byte changed.
    const SHA512: &str = "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425";
    const SHA512_OF_OTHER_CONTENT: &str = "4f79f191298ec7461d60136c60f77c2ae8ddd85dbf6168bb925092d51bfb39b559219b39ae5385ba04946c87f64741385bef90578ea6fe6dac85dbf7ad3f79e1";
    const KEY: ChecksumKey<'static> = ChecksumKey {
        algorithm: "sha512",
        hex: SHA512,
    };

    /// A web server on a loopback port that serves `BODY` to every request and counts them.
    struct FakeHttp {
        url: String,
        requests: Arc<AtomicUsize>,
    }

    impl FakeHttp {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/pkg.tgz", listener.local_addr().unwrap());
            let requests = Arc::new(AtomicUsize::new(0));
            let count = requests.clone();
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let mut seen = Vec::new();
                        let mut buf = [0u8; 1024];
                        while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => seen.extend_from_slice(&buf[..n]),
                            }
                        }
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            BODY.len()
                        );
                        stream.write_all(head.as_bytes()).await.ok();
                        stream.write_all(BODY).await.ok();
                        stream.shutdown().await.ok();
                    });
                }
            });
            Self { url, requests }
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    #[derive(Clone)]
    enum FetchReply {
        Hit(FileDigest),
        Miss,
        Error,
        /// The server is there but cannot be reached right now.
        Unavailable,
        /// The server does not implement Remote Asset.
        Unimplemented,
        /// The server accepts the request and never answers.
        Hang,
    }

    /// How long the fake deadlines are; a hung call is given up on after this.
    const FAKE_DEADLINE: Duration = Duration::from_millis(200);

    /// Records the order of the calls it gets.
    struct FakeAliases {
        fetch: FetchReply,
        upload_fails: bool,
        upload_hangs: bool,
        push_fails: bool,
        push_hangs: bool,
        /// What `resolve` remembers about the server; one per fake, so a test that runs `resolve`
        /// twice against the same fake is two downloads of one session.
        unimplemented: AtomicBool,
        calls: Mutex<Vec<&'static str>>,
        pushed: Mutex<Option<(String, FileDigest)>>,
    }

    impl FakeAliases {
        fn new(fetch: FetchReply) -> Self {
            Self {
                fetch,
                upload_fails: false,
                upload_hangs: false,
                push_fails: false,
                push_hangs: false,
                unimplemented: AtomicBool::new(false),
                calls: Mutex::new(Vec::new()),
                pushed: Mutex::new(None),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }

        fn remote(&self) -> RemoteAsset<'_> {
            RemoteAsset {
                aliases: self,
                unimplemented: &self.unimplemented,
                deadlines: Deadlines {
                    lookup: FAKE_DEADLINE,
                    upload: FAKE_DEADLINE,
                    push: FAKE_DEADLINE,
                },
            }
        }
    }

    #[async_trait]
    impl ChecksumAliases for FakeAliases {
        async fn fetch(
            &self,
            _url: &str,
            _key: ChecksumKey<'_>,
        ) -> buck2_error::Result<Option<FileDigest>> {
            self.calls.lock().unwrap().push("fetch");
            match &self.fetch {
                FetchReply::Hit(digest) => Ok(Some(*digest)),
                FetchReply::Miss => Ok(None),
                FetchReply::Error => Err(buck2_error::buck2_error!(
                    buck2_error::ErrorTag::Input,
                    "fetch failed"
                )),
                // The errors the RE client produces, tagged the way it tags them.
                FetchReply::Unavailable => Err(test_re_error("unavailable", TCode::UNAVAILABLE)),
                FetchReply::Unimplemented => {
                    Err(test_re_error("unimplemented", TCode::UNIMPLEMENTED))
                }
                FetchReply::Hang => std::future::pending().await,
            }
        }

        async fn upload(&self, _digest: &FileDigest) -> buck2_error::Result<()> {
            self.calls.lock().unwrap().push("upload");
            if self.upload_hangs {
                std::future::pending::<()>().await;
            }
            if self.upload_fails {
                return Err(buck2_error::buck2_error!(
                    buck2_error::ErrorTag::Input,
                    "upload failed"
                ));
            }
            Ok(())
        }

        async fn push(
            &self,
            url: &str,
            key: ChecksumKey<'_>,
            digest: &FileDigest,
        ) -> buck2_error::Result<()> {
            self.calls.lock().unwrap().push("push");
            assert_eq!(key, KEY);
            *self.pushed.lock().unwrap() = Some((url.to_owned(), *digest));
            if self.push_hangs {
                std::future::pending::<()>().await;
            }
            if self.push_fails {
                return Err(buck2_error::buck2_error!(
                    buck2_error::ErrorTag::Input,
                    "push failed"
                ));
            }
            Ok(())
        }
    }

    fn body_digest() -> FileDigest {
        FileDigest::from_content(BODY, testing::sha256())
    }

    /// Downloads `url` the way the action does and returns its digest.
    async fn download(
        client: &HttpClient,
        root: &ProjectRootTemp,
        url: &str,
        hex: &str,
    ) -> buck2_error::Result<((), FileDigest)> {
        let config = DigestConfig::leak_new(vec![DigestAlgorithm::Sha256], None).unwrap();
        let digest = http_download(
            client,
            root.path(),
            config,
            ProjectRelativePath::new("out/pkg.tgz").unwrap(),
            url,
            &Checksum::from_pairs(&[("sha512", hex)])?,
            false,
        )
        .await?;
        Ok(((), *digest.data()))
    }

    async fn client() -> HttpClient {
        buck2_certs::certs::maybe_setup_cryptography();
        HttpClientBuilder::https_with_system_roots()
            .await
            .unwrap()
            .build()
    }

    /// Runs `resolve` with a real download against the fake web server. Returns the outcome and
    /// whether `from_cas` was asked, and for which digest.
    async fn run(
        aliases: Option<&FakeAliases>,
        http: &FakeHttp,
        hex: &str,
    ) -> (buck2_error::Result<Resolved<()>>, Option<FileDigest>) {
        run_with_size(aliases, http, hex, None).await
    }

    /// As `run`, for a rule that gave `size_bytes = expected_size`.
    async fn run_with_size(
        aliases: Option<&FakeAliases>,
        http: &FakeHttp,
        hex: &str,
        expected_size: Option<u64>,
    ) -> (buck2_error::Result<Resolved<()>>, Option<FileDigest>) {
        let client = client().await;
        let root = ProjectRootTemp::new().unwrap();
        let asked = Mutex::new(None);
        let remote = aliases.map(FakeAliases::remote);
        // A `resolve` that waits on a step forever must fail this test, not hang it.
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            resolve(
                remote.as_ref(),
                &http.url,
                KEY,
                expected_size,
                |digest| {
                    *asked.lock().unwrap() = Some(digest);
                    async { Ok(Some(())) }
                },
                || download(&client, &root, &http.url, hex),
            ),
        )
        .await
        .expect("resolve did not return: a Remote Asset step has no deadline");
        let asked = *asked.lock().unwrap();
        (outcome, asked)
    }

    /// A hit means the content comes from the CAS: no HTTP request is made, and the digest the
    /// server named is the one handed on.
    #[tokio::test]
    async fn hit_makes_no_http_request() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Hit(body_digest()));

        let (outcome, asked) = run(Some(&aliases), &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::FromCas(()));
        assert_eq!(asked, Some(body_digest()));
        assert_eq!(http.requests(), 0);
        assert_eq!(aliases.calls(), vec!["fetch"]);
    }

    /// A hit whose blob is not the size the rule author gave in `size_bytes` is not used: the CAS
    /// is not asked for it and the file is downloaded (where the same size check then decides).
    #[tokio::test]
    async fn hit_of_the_wrong_size_is_a_miss() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Hit(body_digest()));

        let (outcome, asked) = run_with_size(Some(&aliases), &http, SHA512, Some(7)).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(asked, None);
        assert_eq!(http.requests(), 1);
        assert_eq!(aliases.calls(), vec!["fetch", "upload", "push"]);
    }

    /// A hit of the size that was given is used as any hit is.
    #[tokio::test]
    async fn hit_of_the_given_size_is_used() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Hit(body_digest()));

        let (outcome, asked) = run_with_size(Some(&aliases), &http, SHA512, Some(6)).await;

        assert_matches!(outcome.unwrap(), Resolved::FromCas(()));
        assert_eq!(asked, Some(body_digest()));
        assert_eq!(http.requests(), 0);
    }

    /// If the CAS cannot serve what a hit named after all (it was evicted), the file is
    /// downloaded rather than the build failing.
    #[tokio::test]
    async fn hit_the_cas_cannot_serve_downloads() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Hit(body_digest()));
        let client = client().await;
        let root = ProjectRootTemp::new().unwrap();

        let remote = aliases.remote();
        let outcome = resolve(
            Some(&remote),
            &http.url,
            KEY,
            None,
            |_digest| async { Ok(None::<()>) },
            || download(&client, &root, &http.url, SHA512),
        )
        .await
        .unwrap();

        assert_matches!(outcome, Resolved::Downloaded(()));
        assert_eq!(http.requests(), 1);
    }

    /// If asking the CAS about what a hit named fails (rather than saying it has nothing), the
    /// build still does not fail: the file is downloaded and checked against its checksums. Remote
    /// Asset is never what breaks a build.
    #[tokio::test]
    async fn hit_the_cas_fails_on_downloads() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Hit(body_digest()));
        let client = client().await;
        let root = ProjectRootTemp::new().unwrap();

        let remote = aliases.remote();
        let outcome = resolve(
            Some(&remote),
            &http.url,
            KEY,
            None,
            |_digest| async {
                Err::<Option<()>, _>(buck2_error::buck2_error!(
                    buck2_error::ErrorTag::Input,
                    "the CAS is down"
                ))
            },
            || download(&client, &root, &http.url, SHA512),
        )
        .await
        .unwrap();

        assert_matches!(outcome, Resolved::Downloaded(()));
        assert_eq!(http.requests(), 1);
        // The server is not at fault, so the blob is still recorded afterwards.
        assert_eq!(aliases.calls(), vec!["fetch", "upload", "push"]);
    }

    /// A server that cannot be reached is a miss: the file is downloaded, and the upload and the
    /// push are still tried. It is not remembered as lacking Remote Asset.
    #[tokio::test]
    async fn unavailable_is_a_miss_then_http() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Unavailable);

        let (outcome, asked) = run(Some(&aliases), &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(asked, None);
        assert_eq!(http.requests(), 1);
        assert_eq!(aliases.calls(), vec!["fetch", "upload", "push"]);
        assert!(aliases.remote().usable());
    }

    /// A server without Remote Asset is asked once. The download that finds out goes to the URL
    /// and does not upload or push, and the next one makes no Remote Asset call at all.
    #[tokio::test]
    async fn unimplemented_is_remembered() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Unimplemented);

        let (outcome, _) = run(Some(&aliases), &http, SHA512).await;
        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(aliases.calls(), vec!["fetch"]);
        assert!(!aliases.remote().usable());

        let (outcome, _) = run(Some(&aliases), &http, SHA512).await;
        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        // No new call of any kind: still the one `fetch`.
        assert_eq!(aliases.calls(), vec!["fetch"]);
        assert_eq!(http.requests(), 2);
    }

    /// A lookup that is never answered is given up on at its deadline, and the file is downloaded:
    /// the build is delayed by the deadline and no more.
    #[tokio::test]
    async fn lookup_timeout_is_a_miss() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Hang);

        let started = std::time::Instant::now();
        let (outcome, asked) = run(Some(&aliases), &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(asked, None);
        assert_eq!(http.requests(), 1);
        assert_eq!(aliases.calls(), vec!["fetch", "upload", "push"]);
        // The deadline passed (so something did wait for it), and nothing waited much longer.
        assert!(started.elapsed() >= FAKE_DEADLINE);
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    /// An upload that is never acknowledged is given up on, the push that needed it is skipped,
    /// and the build succeeds.
    #[tokio::test]
    async fn upload_timeout_skips_the_push() {
        let http = FakeHttp::start().await;
        let mut aliases = FakeAliases::new(FetchReply::Miss);
        aliases.upload_hangs = true;

        let (outcome, _) = run(Some(&aliases), &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(aliases.calls(), vec!["fetch", "upload"]);
    }

    /// A push that is never answered is given up on and the build succeeds.
    #[tokio::test]
    async fn push_timeout_does_not_fail_the_build() {
        let http = FakeHttp::start().await;
        let mut aliases = FakeAliases::new(FetchReply::Miss);
        aliases.push_hangs = true;

        let (outcome, _) = run(Some(&aliases), &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(aliases.calls(), vec!["fetch", "upload", "push"]);
    }

    /// A miss downloads, then uploads, then records, in that order, and the recorded digest is the
    /// sha256 of the downloaded bytes.
    #[tokio::test]
    async fn miss_downloads_then_uploads_then_pushes() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Miss);

        let (outcome, asked) = run(Some(&aliases), &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(asked, None);
        assert_eq!(http.requests(), 1);
        assert_eq!(aliases.calls(), vec!["fetch", "upload", "push"]);
        let (url, digest) = aliases.pushed.lock().unwrap().clone().unwrap();
        assert_eq!(url, http.url);
        assert_eq!(digest, body_digest());
    }

    /// Any lookup error is the same as a miss.
    #[tokio::test]
    async fn fetch_error_downloads() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Error);

        let (outcome, _) = run(Some(&aliases), &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(http.requests(), 1);
        assert_eq!(aliases.calls(), vec!["fetch", "upload", "push"]);
    }

    /// A push the server refuses never fails the build.
    #[tokio::test]
    async fn push_failure_does_not_fail_the_build() {
        let http = FakeHttp::start().await;
        let mut aliases = FakeAliases::new(FetchReply::Miss);
        aliases.push_fails = true;

        let (outcome, _) = run(Some(&aliases), &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(aliases.calls(), vec!["fetch", "upload", "push"]);
    }

    /// A failed upload skips the push (the server would refuse it) and does not fail the build.
    #[tokio::test]
    async fn upload_failure_skips_the_push() {
        let http = FakeHttp::start().await;
        let mut aliases = FakeAliases::new(FetchReply::Miss);
        aliases.upload_fails = true;

        let (outcome, _) = run(Some(&aliases), &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(aliases.calls(), vec!["fetch", "upload"]);
    }

    /// Content that does not match the checksum fails the build, and is not recorded as the content
    /// behind that checksum.
    #[tokio::test]
    async fn download_that_fails_the_checksum_records_nothing() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Miss);

        let (outcome, _) = run(Some(&aliases), &http, SHA512_OF_OTHER_CONTENT).await;

        assert!(outcome.is_err());
        assert_eq!(aliases.calls(), vec!["fetch"]);
    }

    /// Without remote execution there is no Remote Asset call to make, and the file is just
    /// downloaded and verified.
    #[tokio::test]
    async fn without_remote_execution_it_is_http_only() {
        let http = FakeHttp::start().await;

        let (outcome, asked) = run(None, &http, SHA512).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(asked, None);
        assert_eq!(http.requests(), 1);

        // And the checksum is still enforced.
        let http = FakeHttp::start().await;
        let (outcome, _) = run(None, &http, SHA512_OF_OTHER_CONTENT).await;
        assert!(outcome.is_err());
    }

    /// Remote Asset is only used when there is a CAS to ask and it is keyed by sha256.
    #[test]
    fn aliases_need_a_sha256_cas() {
        assert!(aliases_usable(true, testing::sha256()));
        assert!(aliases_usable(true, testing::sha256_sha1()));
        assert!(!aliases_usable(false, testing::sha256()));
        assert!(!aliases_usable(true, testing::sha1()));
        assert!(!aliases_usable(true, testing::blake3()));
    }
}
