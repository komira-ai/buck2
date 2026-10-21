/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

//! How a `download_file` declared only by a Subresource Integrity token (`sri`) gets its content.
//!
//! The sha256 that names such a file in the CAS is unknown until the file has been read, so the
//! action cannot ask the CAS for it the way it does when `sha256` is given. If remote execution
//! is configured, a Remote Asset server is asked first which CAS blob is known under the token. A
//! hit gives the sha256 and size, and the normal CAS path runs, so no bytes move. On a miss (or any
//! error) the file is downloaded and checked against the token, and then, so the next client does
//! not have to download it, it is uploaded to the CAS and the server is told which blob it is.

use std::future::Future;

use async_trait::async_trait;
use buck2_common::cas_digest::CasDigestConfig;
use buck2_common::cas_digest::DigestAlgorithm;
use buck2_common::file_ops::metadata::FileDigest;
use buck2_execute::materialize::http::Sri;

/// What the download of an SRI-declared file needs from the Remote Asset server and the CAS
/// behind it. All digests are sha256.
#[async_trait]
pub(crate) trait SriAliases: Send + Sync {
    /// The blob the server knows under `sri` at `url`, if any. `Ok(None)` is a miss.
    ///
    /// Trust: the sha512 in `sri` is not checked on this path. A hit is trusted to the extent the
    /// Remote Asset server and the CAS are trusted (the same endpoint already controls CAS
    /// contents and action outputs), and the server is expected to have verified sha512 before it
    /// recorded the alias. A hit can only name a blob that exists in the CAS, and the caller
    /// rechecks presence through `declare_from_cas`. sha512 is verified client-side only when the
    /// file is downloaded over HTTP. A stricter option would be a config key that disables alias
    /// lookups.
    async fn fetch(&self, url: &str, sri: &Sri) -> buck2_error::Result<Option<FileDigest>>;

    /// Puts the downloaded file, whose digest is `digest`, in the CAS. Returns once the server has
    /// acknowledged it.
    async fn upload(&self, digest: &FileDigest) -> buck2_error::Result<()>;

    /// Records that the blob `digest`, which the server must already hold, is the content behind
    /// `sri` at `url`.
    async fn push(&self, url: &str, sri: &Sri, digest: &FileDigest) -> buck2_error::Result<()>;
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

/// Gets the content of the file at `url` whose SRI token is `sri`.
///
/// `from_cas` turns the digest a hit names into the action's value, or says the CAS cannot serve
/// it after all (`None`). `download` downloads and verifies the file and returns its value and
/// digest. With `aliases` `None` (no remote execution) nothing but `download` runs.
///
/// Telling the server about the blob is best effort: whatever fails there is logged and the build
/// goes on.
pub(crate) async fn resolve<T, FromCasFut, DownloadFut>(
    aliases: Option<&dyn SriAliases>,
    url: &str,
    sri: &Sri,
    from_cas: impl FnOnce(FileDigest) -> FromCasFut,
    download: impl FnOnce() -> DownloadFut,
) -> buck2_error::Result<Resolved<T>>
where
    FromCasFut: Future<Output = buck2_error::Result<Option<T>>> + Send,
    DownloadFut: Future<Output = buck2_error::Result<(T, FileDigest)>> + Send,
    T: Send,
{
    let Some(aliases) = aliases else {
        return Ok(Resolved::Downloaded(download().await?.0));
    };

    match aliases.fetch(url, sri).await {
        Ok(Some(digest)) => {
            if let Some(value) = from_cas(digest).await? {
                return Ok(Resolved::FromCas(value));
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::debug!(
                "Remote Asset lookup of `{}` failed, downloading instead: {:#}",
                url,
                e
            );
        }
    }

    let (value, digest) = download().await?;

    // The server refuses an alias for a blob it does not hold, so the upload has to be
    // acknowledged before the push is sent.
    match aliases.upload(&digest).await {
        Ok(()) => {
            if let Err(e) = aliases.push(url, sri, &digest).await {
                tracing::warn!(
                    "Could not record `{}` with the Remote Asset server: {:#}",
                    url,
                    e
                );
            }
        }
        Err(e) => {
            tracing::warn!("Could not upload `{}` to the CAS: {:#}", url, e);
        }
    }

    Ok(Resolved::Downloaded(value))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use assert_matches::assert_matches;
    use buck2_common::cas_digest::testing;
    use buck2_core::fs::project::ProjectRootTemp;
    use buck2_core::fs::project_rel_path::ProjectRelativePath;
    use buck2_execute::digest_config::DigestConfig;
    use buck2_execute::materialize::http::Checksum;
    use buck2_execute::materialize::http::http_download;
    use buck2_http::HttpClient;
    use buck2_http::HttpClientBuilder;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    use super::*;

    const BODY: &[u8] = b"foobar";
    // sha512 of "foobar", and of "foobaz": a download with one byte changed.
    const SRI: &str = "sha512-ClAmHr0aOQ/tK/Mm8mc8FFWCpjQtUjIElz0CGTN/gWFqgGmwElh89WNfaSXxtWw2AjDBmyc1AO4BPgMGAb8kJQ==";
    const SRI_OF_OTHER_CONTENT: &str = "sha512-T3nxkSmOx0YdYBNsYPd8Kujd2F2/YWi7klCS1Rv7ObVZIZs5rlOFugSUbIf2R0E4W++QV46m/m2shdv3rT954Q==";

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
                        let _ = stream.write_all(head.as_bytes()).await;
                        let _ = stream.write_all(BODY).await;
                        let _ = stream.shutdown().await;
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
    }

    /// Records the order of the calls it gets.
    struct FakeAliases {
        fetch: FetchReply,
        upload_fails: bool,
        push_fails: bool,
        calls: Mutex<Vec<&'static str>>,
        pushed: Mutex<Option<(String, FileDigest)>>,
    }

    impl FakeAliases {
        fn new(fetch: FetchReply) -> Self {
            Self {
                fetch,
                upload_fails: false,
                push_fails: false,
                calls: Mutex::new(Vec::new()),
                pushed: Mutex::new(None),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SriAliases for FakeAliases {
        async fn fetch(&self, _url: &str, _sri: &Sri) -> buck2_error::Result<Option<FileDigest>> {
            self.calls.lock().unwrap().push("fetch");
            match &self.fetch {
                FetchReply::Hit(digest) => Ok(Some(digest.clone())),
                FetchReply::Miss => Ok(None),
                FetchReply::Error => Err(buck2_error::buck2_error!(
                    buck2_error::ErrorTag::Input,
                    "fetch failed"
                )),
            }
        }

        async fn upload(&self, _digest: &FileDigest) -> buck2_error::Result<()> {
            self.calls.lock().unwrap().push("upload");
            if self.upload_fails {
                return Err(buck2_error::buck2_error!(
                    buck2_error::ErrorTag::Input,
                    "upload failed"
                ));
            }
            Ok(())
        }

        async fn push(&self, url: &str, sri: &Sri, digest: &FileDigest) -> buck2_error::Result<()> {
            self.calls.lock().unwrap().push("push");
            assert_eq!(sri.as_str(), SRI);
            *self.pushed.lock().unwrap() = Some((url.to_owned(), digest.clone()));
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
        sri: &str,
    ) -> buck2_error::Result<((), FileDigest)> {
        let config = DigestConfig::leak_new(vec![DigestAlgorithm::Sha256], None).unwrap();
        let digest = http_download(
            client,
            root.path(),
            config,
            ProjectRelativePath::new("out/pkg.tgz").unwrap(),
            url,
            &Checksum::new(None, None, Some(sri))?,
            false,
        )
        .await?;
        Ok(((), digest.data().clone()))
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
        sri: &str,
    ) -> (buck2_error::Result<Resolved<()>>, Option<FileDigest>) {
        let client = client().await;
        let root = ProjectRootTemp::new().unwrap();
        let asked = Mutex::new(None);
        let outcome = resolve(
            aliases.map(|a| a as &dyn SriAliases),
            &http.url,
            &Sri::parse(SRI).unwrap(),
            |digest| {
                *asked.lock().unwrap() = Some(digest);
                async { Ok(Some(())) }
            },
            || download(&client, &root, &http.url, sri),
        )
        .await;
        let asked = asked.lock().unwrap().clone();
        (outcome, asked)
    }

    /// A hit means the content comes from the CAS: no HTTP request is made, and the digest the
    /// server named is the one handed on. Catches a hit that is ignored.
    #[tokio::test]
    async fn hit_makes_no_http_request() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Hit(body_digest()));

        let (outcome, asked) = run(Some(&aliases), &http, SRI).await;

        assert_matches!(outcome.unwrap(), Resolved::FromCas(()));
        assert_eq!(asked, Some(body_digest()));
        assert_eq!(http.requests(), 0);
        assert_eq!(aliases.calls(), vec!["fetch"]);
    }

    /// If the CAS cannot serve what a hit named after all (it was evicted), the file is
    /// downloaded rather than the build failing.
    #[tokio::test]
    async fn hit_the_cas_cannot_serve_downloads() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Hit(body_digest()));
        let client = client().await;
        let root = ProjectRootTemp::new().unwrap();

        let outcome = resolve(
            Some(&aliases as &dyn SriAliases),
            &http.url,
            &Sri::parse(SRI).unwrap(),
            |_digest| async { Ok(None::<()>) },
            || download(&client, &root, &http.url, SRI),
        )
        .await
        .unwrap();

        assert_matches!(outcome, Resolved::Downloaded(()));
        assert_eq!(http.requests(), 1);
    }

    /// A miss downloads, then uploads, then records, in that order. Catches a push that is sent
    /// before the upload: the server would refuse an alias for a blob it does not hold yet. The
    /// recorded digest is the sha256 of the downloaded bytes.
    #[tokio::test]
    async fn miss_downloads_then_uploads_then_pushes() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Miss);

        let (outcome, asked) = run(Some(&aliases), &http, SRI).await;

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

        let (outcome, _) = run(Some(&aliases), &http, SRI).await;

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

        let (outcome, _) = run(Some(&aliases), &http, SRI).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(aliases.calls(), vec!["fetch", "upload", "push"]);
    }

    /// A failed upload skips the push (the server would refuse it) and does not fail the build.
    #[tokio::test]
    async fn upload_failure_skips_the_push() {
        let http = FakeHttp::start().await;
        let mut aliases = FakeAliases::new(FetchReply::Miss);
        aliases.upload_fails = true;

        let (outcome, _) = run(Some(&aliases), &http, SRI).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(aliases.calls(), vec!["fetch", "upload"]);
    }

    /// Content that does not match the token fails the build, and is not recorded as the content
    /// behind that token.
    #[tokio::test]
    async fn download_that_fails_the_checksum_records_nothing() {
        let http = FakeHttp::start().await;
        let aliases = FakeAliases::new(FetchReply::Miss);

        let (outcome, _) = run(Some(&aliases), &http, SRI_OF_OTHER_CONTENT).await;

        assert!(outcome.is_err());
        assert_eq!(aliases.calls(), vec!["fetch"]);
    }

    /// Without remote execution there is no Remote Asset call to make, and the file is just
    /// downloaded and verified.
    #[tokio::test]
    async fn without_remote_execution_it_is_http_only() {
        let http = FakeHttp::start().await;

        let (outcome, asked) = run(None, &http, SRI).await;

        assert_matches!(outcome.unwrap(), Resolved::Downloaded(()));
        assert_eq!(asked, None);
        assert_eq!(http.requests(), 1);

        // And the checksum is still enforced.
        let http = FakeHttp::start().await;
        let (outcome, _) = run(None, &http, SRI_OF_OTHER_CONTENT).await;
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
