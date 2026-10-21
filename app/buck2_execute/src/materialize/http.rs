/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::fmt;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use allocative::Allocative;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use buck2_common::cas_digest::CasDigestConfig;
use buck2_common::cas_digest::DigestAlgorithmFamily;
use buck2_common::cas_digest::SHA1_SIZE;
use buck2_common::cas_digest::SHA256_SIZE;
use buck2_common::file_ops::metadata::FileDigest;
use buck2_common::file_ops::metadata::TrackedFileDigest;
use buck2_core::fs::project::ProjectRoot;
use buck2_core::fs::project_rel_path::ProjectRelativePath;
use buck2_error::BuckErrorContext;
use buck2_fs::error::IoResultExt;
use buck2_fs::fs_util;
use buck2_http::HttpClient;
use buck2_http::retries::HttpError;
use buck2_http::retries::HttpErrorForRetry;
use buck2_http::retries::IntoBuck2Error;
use buck2_http::retries::http_retry;
use bytes::Bytes;
use digest::DynDigest;
use dupe::Dupe;
use futures::StreamExt;
use futures::stream::Stream;
use hyper::Response;
use pagable::Pagable;
use sha1::Digest;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Sha512;
use smallvec::SmallVec;

use crate::digest_config::DigestConfig;

#[derive(Debug, Clone, Dupe, Allocative, Pagable)]
pub enum Checksum {
    Sha1(Arc<str>),
    Sha256(Arc<str>),
    Both {
        sha1: Arc<str>,
        sha256: Arc<str>,
    },
    /// Only a Subresource Integrity token. The content is verified while it is downloaded, but
    /// its digest is not known up front.
    Sri(Sri),
}

/// The hash algorithms an SRI token can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SriAlgorithm {
    Sha256,
    Sha512,
}

impl SriAlgorithm {
    fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// A single [Subresource Integrity](https://www.w3.org/TR/SRI/) hash: `<algorithm>-<base64
/// digest>`, with sha256 and sha512 the algorithms accepted. It is stored in the form it was
/// validated in, so it can be sent as is to a server that is asked about the same content.
#[derive(Debug, Clone, Dupe, PartialEq, Eq, Allocative, Pagable)]
pub struct Sri(Arc<str>);

impl Sri {
    pub fn parse(sri: &str) -> buck2_error::Result<Self> {
        let (algorithm, digest) =
            sri.split_once('-')
                .ok_or_else(|| DownloadFileError::InvalidSri {
                    sri: sri.to_owned(),
                    reason: "expected `<algorithm>-<base64 digest>`",
                })?;
        let algorithm = match algorithm {
            "sha256" => SriAlgorithm::Sha256,
            "sha512" => SriAlgorithm::Sha512,
            other => {
                return Err(DownloadFileError::UnsupportedSriAlgorithm {
                    sri: sri.to_owned(),
                    algorithm: other.to_owned(),
                }
                .into());
            }
        };
        let decoded = STANDARD
            .decode(digest)
            .map_err(|_| DownloadFileError::InvalidSri {
                sri: sri.to_owned(),
                reason: "the digest is not padded standard base64",
            })?;
        if decoded.len() != algorithm.digest_len() {
            return Err(DownloadFileError::InvalidSri {
                sri: sri.to_owned(),
                reason: "the digest has the wrong length for its algorithm",
            }
            .into());
        }
        Ok(Self(Arc::from(sri)))
    }

    /// The token, as validated: `<algorithm>-<base64 digest>`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn algorithm(&self) -> SriAlgorithm {
        // `parse` only builds values with a known algorithm before the first `-`.
        match self.0.split_once('-') {
            Some(("sha256", _)) => SriAlgorithm::Sha256,
            _ => SriAlgorithm::Sha512,
        }
    }

    /// The base64 digest, without the algorithm prefix.
    pub fn digest_base64(&self) -> &str {
        self.0.split_once('-').map_or("", |(_, digest)| digest)
    }
}

#[derive(buck2_error::Error, Debug)]
#[buck2(tag = Input)]
enum DownloadFileError {
    #[error("Must pass in at least one checksum (e.g. `sha1 = ...`)")]
    MissingChecksum,
    #[error("`sri` cannot be combined with `sha1` or `sha256`; pass one or the other")]
    SriWithOtherChecksum,
    #[error("Invalid `sri` argument `{sri}`: {reason}")]
    InvalidSri { sri: String, reason: &'static str },
    #[error(
        "Unsupported hash algorithm `{algorithm}` in `sri` argument `{sri}`, only `sha256` and `sha512` are supported"
    )]
    UnsupportedSriAlgorithm { sri: String, algorithm: String },
    #[error("Invalid digest for `{digest_type}` argument, expected length of {expected_len} but got {}, digest `{digest}`", digest.len())]
    InvalidDigestLength {
        digest: String,
        expected_len: usize,
        digest_type: &'static str,
    },
    #[error(
        "Invalid digest for `{digest_type}` argument, expected 0-9 a-z hex characters, but got `{bad_char}`, digest `{digest}`"
    )]
    InvalidDigestCharacter {
        digest: String,
        bad_char: char,
        digest_type: &'static str,
    },
}

impl Checksum {
    pub fn new(
        sha1: Option<&str>,
        sha256: Option<&str>,
        sri: Option<&str>,
    ) -> buck2_error::Result<Self> {
        fn is_hex_digit(x: char) -> bool {
            let x = x.to_ascii_lowercase();
            x.is_ascii_digit() || ('a'..='f').contains(&x)
        }

        fn validate_digest(
            digest: Option<&str>,
            digest_len: usize,
            digest_type: &'static str,
        ) -> buck2_error::Result<Option<Arc<str>>> {
            match digest {
                None => Ok(None),
                Some(digest) => {
                    let expected_len = digest_len * 2;
                    if digest.len() != expected_len {
                        return Err(DownloadFileError::InvalidDigestLength {
                            digest: digest.to_owned(),
                            expected_len,
                            digest_type,
                        }
                        .into());
                    }
                    if let Some(bad_char) = digest.chars().find(|x| !is_hex_digit(*x)) {
                        return Err(DownloadFileError::InvalidDigestCharacter {
                            digest: digest.to_owned(),
                            bad_char,
                            digest_type,
                        }
                        .into());
                    }
                    Ok(Some(Arc::from(digest.to_ascii_lowercase())))
                }
            }
        }

        if let Some(sri) = sri {
            if sha1.is_some() || sha256.is_some() {
                return Err(DownloadFileError::SriWithOtherChecksum.into());
            }
            return Ok(Checksum::Sri(Sri::parse(sri)?));
        }

        match (
            validate_digest(sha1, SHA1_SIZE, "sha1")?,
            validate_digest(sha256, SHA256_SIZE, "sha256")?,
        ) {
            (Some(sha1), None) => Ok(Checksum::Sha1(sha1)),
            (None, Some(sha256)) => Ok(Checksum::Sha256(sha256)),
            (Some(sha1), Some(sha256)) => Ok(Checksum::Both { sha1, sha256 }),
            (None, None) => Err(DownloadFileError::MissingChecksum.into()),
        }
    }

    pub fn sha1(&self) -> Option<&str> {
        match self {
            Self::Sha1(sha1) => Some(sha1),
            Self::Sha256(..) | Self::Sri(..) => None,
            Self::Both { sha1, .. } => Some(sha1),
        }
    }

    pub fn sha256(&self) -> Option<&str> {
        match self {
            Self::Sha1(..) | Self::Sri(..) => None,
            Self::Sha256(sha256) => Some(sha256),
            Self::Both { sha256, .. } => Some(sha256),
        }
    }

    pub fn sri(&self) -> Option<&Sri> {
        match self {
            Self::Sri(sri) => Some(sri),
            Self::Sha1(..) | Self::Sha256(..) | Self::Both { .. } => None,
        }
    }
}

#[derive(Debug, buck2_error::Error)]
#[buck2(tag = Http)]
enum HttpHeadError {
    #[error("Error performing http_head request")]
    Client(#[source] HttpError),
}

impl From<HttpError> for HttpHeadError {
    fn from(e: HttpError) -> Self {
        Self::Client(e)
    }
}

#[derive(Debug, buck2_error::Error)]
#[buck2(tag = Http)]
enum HttpDownloadError {
    #[error("Error performing http_download request")]
    Client(#[source] HttpError),

    #[error(
        "Invalid {digest_kind} digest. Expected {expected}, got {obtained}. URL: {url}. {debug}"
    )]
    #[buck2(input)]
    InvalidChecksum {
        digest_kind: &'static str,
        expected: String,
        obtained: String,
        url: String,
        debug: Box<MaybeResponseDebugInfo>,
    },

    #[error(
        "Received invalid {kind} digest from {url}; perhaps this is not allowed on vpnless?. Expected {want}, got {got}. {debug}"
    )]
    MaybeNotAllowedOnVpnless {
        kind: &'static str,
        want: String,
        got: String,
        url: String,
        debug: Box<MaybeResponseDebugInfo>,
    },

    #[error(transparent)]
    IoError(buck2_error::Error),
}

impl HttpDownloadError {
    fn into_final(mut self) -> Self {
        match &mut self {
            Self::Client(..) | Self::IoError(..) => {}
            Self::InvalidChecksum { debug, .. } | Self::MaybeNotAllowedOnVpnless { debug, .. } => {
                debug.is_final = true;
            }
        }

        self
    }
}

impl From<HttpError> for HttpDownloadError {
    fn from(e: HttpError) -> Self {
        Self::Client(e)
    }
}

impl HttpErrorForRetry for HttpHeadError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Client(e) => e.is_retryable(),
        }
    }
}

impl HttpErrorForRetry for HttpDownloadError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Client(e) => e.is_retryable(),
            Self::InvalidChecksum { .. } => {
                // Normally, invalid checksums don't make sense to retry, but the HTTP servers we
                // talk to internally tend to happily return 200s and give you the error in the
                // message body... so it's a good idea to retry those.
                cfg!(fbcode_build)
            }
            Self::IoError(..) | Self::MaybeNotAllowedOnVpnless { .. } => false,
        }
    }
}

impl IntoBuck2Error for HttpHeadError {
    fn into_buck2_error(self) -> buck2_error::Error {
        buck2_error::Error::from(self)
    }
}

impl IntoBuck2Error for HttpDownloadError {
    fn into_buck2_error(self) -> buck2_error::Error {
        buck2_error::Error::from(self)
    }
}

pub async fn http_head(client: &HttpClient, url: &str) -> buck2_error::Result<Response<()>> {
    let response = http_retry(
        || async {
            client
                .head(url)
                .await
                .map_err(|e| HttpHeadError::Client(HttpError::Client(e)))
        },
        vec![2, 4, 8].into_iter().map(Duration::from_secs).collect(),
    )
    .await?;
    Ok(response)
}

pub async fn http_download(
    client: &HttpClient,
    fs: &ProjectRoot,
    digest_config: DigestConfig,
    path: &ProjectRelativePath,
    url: &str,
    checksum: &Checksum,
    executable: bool,
) -> buck2_error::Result<TrackedFileDigest> {
    let abs_path = fs.resolve(path);
    if let Some(dir) = abs_path.parent() {
        fs_util::create_dir_all(dir)?;
    }

    Ok(http_retry(
        || async {
            let response = client
                .get(url)
                .await
                .map_err(|e| HttpDownloadError::Client(HttpError::Client(e)))?;

            let (head, stream) = response.into_parts();
            let file = fs_util::create_file(&abs_path)
                .categorize_internal()
                .map_err(HttpDownloadError::IoError)?;
            let buf_writer = std::io::BufWriter::new(file);

            let digest = copy_and_hash(
                url,
                Some(head),
                &abs_path,
                stream,
                buf_writer,
                digest_config.cas_digest_config(),
                checksum,
                client.supports_vpnless(),
            )
            .await?;

            if executable {
                fs.set_executable(path)
                    .map_err(HttpDownloadError::IoError)?;
            }

            Result::<_, HttpDownloadError>::Ok(TrackedFileDigest::new(
                digest,
                digest_config.cas_digest_config(),
            ))
        },
        vec![2, 4, 8].into_iter().map(Duration::from_secs).collect(),
    )
    .await
    .map_err(|e| e.into_final())?)
}

/// Copy a stream into a writer while producing its digest and checksumming it.
async fn copy_and_hash(
    url: &str,
    head: Option<http::response::Parts>,
    abs_path: &(impl std::fmt::Display + ?Sized),
    mut stream: impl Stream<Item = Result<Bytes, hyper::Error>> + Unpin,
    mut writer: impl Write,
    digest_config: CasDigestConfig,
    checksum: &Checksum,
    is_vpnless: bool,
) -> Result<FileDigest, HttpDownloadError> {
    let mut digester = FileDigest::digester(digest_config);

    // For each checksum entry we have, we're going to add a validator. We might have to create
    // a new hasher, or reuse the `FileDigest::digester` if it matches.

    enum Validator {
        PrimaryDigest,
        ExtraDigest(Box<dyn DynDigest + Send>),
        /// Like `ExtraDigest`, but the checksum is base64 rather than hex, as in an SRI token.
        ExtraDigestBase64(Box<dyn DynDigest + Send>),
    }

    let mut validators = SmallVec::<[_; 2]>::new();

    if let Some(sha1) = checksum.sha1() {
        let validator = if digester.algorithm() == DigestAlgorithmFamily::Sha1 {
            Validator::PrimaryDigest
        } else {
            Validator::ExtraDigest(Box::new(Sha1::new()) as _)
        };

        validators.push((validator, sha1, "sha1"));
    }

    if let Some(sha256) = checksum.sha256() {
        let validator = if digester.algorithm() == DigestAlgorithmFamily::Sha256 {
            Validator::PrimaryDigest
        } else {
            Validator::ExtraDigest(Box::new(Sha256::new()) as _)
        };

        validators.push((validator, sha256, "sha256"));
    }

    if let Some(sri) = checksum.sri() {
        let (hasher, kind): (Box<dyn DynDigest + Send>, _) = match sri.algorithm() {
            SriAlgorithm::Sha256 => (Box::new(Sha256::new()), "sri sha256"),
            SriAlgorithm::Sha512 => (Box::new(Sha512::new()), "sri sha512"),
        };
        validators.push((
            Validator::ExtraDigestBase64(hasher),
            sri.digest_base64(),
            kind,
        ));
    }

    let mut buff = DebugBuffer::new(512);

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| HttpError::Transfer {
            received: digester.bytes_read(),
            url: url.to_owned(),
            source,
        })?;

        buff.peek(&chunk);

        writer
            .write(&chunk)
            .with_buck_error_context(|| format!("write({abs_path})"))
            .map_err(HttpDownloadError::IoError)?;

        digester.update(&chunk);
        for (validator, _expected, _kind) in validators.iter_mut() {
            match validator {
                Validator::ExtraDigest(hasher) | Validator::ExtraDigestBase64(hasher) => {
                    hasher.update(&chunk);
                }
                Validator::PrimaryDigest => {}
            }
        }
    }
    writer
        .flush()
        .with_buck_error_context(|| format!("flush({abs_path})"))
        .map_err(HttpDownloadError::IoError)?;

    let digest = digester.finalize();

    // Validate
    for (validator, expected, kind) in validators {
        let obtained = match validator {
            Validator::PrimaryDigest => digest.raw_digest().to_string(),
            Validator::ExtraDigest(hasher) => hex::encode(hasher.finalize()),
            Validator::ExtraDigestBase64(hasher) => STANDARD.encode(hasher.finalize()),
        };

        if expected != obtained {
            let debug = Box::new(MaybeResponseDebugInfo {
                bytes_seen: buff.bytes_seen,
                buff: buff.to_utf8().map(ToOwned::to_owned),
                head,
                is_final: false,
            });

            if is_vpnless {
                return Err(HttpDownloadError::MaybeNotAllowedOnVpnless {
                    kind,
                    want: expected.to_owned(),
                    got: obtained,
                    url: url.to_owned(),
                    debug,
                });
            }
            return Err(HttpDownloadError::InvalidChecksum {
                digest_kind: kind,
                expected: expected.to_owned(),
                obtained,
                url: url.to_owned(),
                debug,
            });
        }
    }

    Ok(digest)
}

struct DebugBuffer {
    bytes_seen: u64,
    max_size: usize,
    buff: Vec<u8>,
}

impl DebugBuffer {
    fn new(max_size: usize) -> Self {
        Self {
            bytes_seen: 0,
            max_size,
            buff: Vec::new(),
        }
    }

    fn peek(&mut self, chunk: &[u8]) {
        // unwrap safety: we can't possibly have a chunk whose length can't be represented with 64
        // bits.
        self.bytes_seen += u64::try_from(chunk.len()).unwrap();

        if self.buff.len() < self.max_size {
            let want_bytes = std::cmp::min(chunk.len(), self.max_size - self.buff.len());
            self.buff.extend(&chunk[..want_bytes]);
        }
    }

    fn to_utf8(&self) -> Option<&str> {
        match std::str::from_utf8(&self.buff) {
            Ok(utf8) => Some(utf8),
            Err(e) => {
                let valid_up_to = e.valid_up_to();

                // If at least 50% of the buffer is valid UTF8, let's show it.
                if valid_up_to >= (self.max_size / 2) {
                    std::str::from_utf8(&self.buff[..valid_up_to]).ok()
                } else {
                    None
                }
            }
        }
    }
}

/// A little helper to avoid showing the debug data in http_retry because that's reall verbose.
#[derive(Debug)]
struct MaybeResponseDebugInfo {
    bytes_seen: u64,
    buff: Option<String>,
    head: Option<http::response::Parts>,
    is_final: bool,
}

impl fmt::Display for MaybeResponseDebugInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Received {} bytes.", self.bytes_seen)?;

        if !self.is_final {
            return Ok(());
        }

        if let Some(head) = &self.head {
            let interesting_headers = ["error-mid", "x-fb-debug"]
                .into_iter()
                .filter_map(|header| {
                    head.headers
                        .get(header)
                        .and_then(|h| h.to_str().ok())
                        .map(|header_value| (header, header_value))
                })
                .collect::<Vec<_>>();

            write!(f, "\n\nRelevant debug headers:\n")?;
            if interesting_headers.is_empty() {
                write!(f, "<none>")?;
            } else {
                for (header, header_value) in interesting_headers {
                    writeln!(f, "{header}: {header_value}")?;
                }
            }
        }

        match &self.buff {
            Some(text) => {
                write!(f, "\n\nResponse started with:\n\n{text}")?;
            }
            None => {
                write!(f, "Response is not UTF-8")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use buck2_common::cas_digest::testing;
    use futures::stream;

    use super::*;

    async fn do_test(
        digest_config: CasDigestConfig,
        checksum: &Checksum,
    ) -> Result<(FileDigest, Vec<u8>), HttpDownloadError> {
        let mut out = Vec::new();

        let digest = copy_and_hash(
            "test",
            None,
            "test",
            stream::iter(vec![Ok(Bytes::from("foo")), Ok(Bytes::from("bar"))]),
            &mut out,
            digest_config,
            checksum,
            false,
        )
        .await?;

        Ok((digest, out))
    }

    #[tokio::test]
    async fn test_copy_and_hash_ok() -> buck2_error::Result<()> {
        let (digest, bytes) = do_test(
            testing::blake3(),
            &Checksum::Both {
                sha1: Arc::from("8843d7f92416211de9ebb963ff4ce28125932878"),
                sha256: Arc::from(
                    "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
                ),
            },
        )
        .await?;

        assert_eq!(
            digest.to_string(),
            "aa51dcd43d5c6c5203ee16906fd6b35db298b9b2e1de3fce81811d4806b76b7d:6"
        );

        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "foobar");

        Ok(())
    }

    #[tokio::test]
    async fn test_copy_and_hash_invalid_primary_hash() -> buck2_error::Result<()> {
        assert_matches!(
            do_test(testing::sha1(), &Checksum::Sha1(Arc::from("oops"))).await,
            Err(HttpDownloadError::InvalidChecksum { .. })
        );

        assert_matches!(
            do_test(testing::sha256(), &Checksum::Sha256(Arc::from("oops"))).await,
            Err(HttpDownloadError::InvalidChecksum { .. })
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_copy_and_hash_invalid_secondary_hash() -> buck2_error::Result<()> {
        assert_matches!(
            do_test(testing::blake3(), &Checksum::Sha1(Arc::from("oops"))).await,
            Err(HttpDownloadError::InvalidChecksum { .. })
        );

        assert_matches!(
            do_test(testing::blake3(), &Checksum::Sha256(Arc::from("oops"))).await,
            Err(HttpDownloadError::InvalidChecksum { .. })
        );

        Ok(())
    }

    // `sha512` and `sha256` of "foobar", in SRI form.
    const FOOBAR_SHA512_SRI: &str = "sha512-ClAmHr0aOQ/tK/Mm8mc8FFWCpjQtUjIElz0CGTN/gWFqgGmwElh89WNfaSXxtWw2AjDBmyc1AO4BPgMGAb8kJQ==";
    const FOOBAR_SHA256_SRI: &str = "sha256-w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=";
    // The sha512 of "foobaz": what a download would be checked against if one byte were flipped.
    const FOOBAZ_SHA512_SRI: &str = "sha512-T3nxkSmOx0YdYBNsYPd8Kujd2F2/YWi7klCS1Rv7ObVZIZs5rlOFugSUbIf2R0E4W++QV46m/m2shdv3rT954Q==";

    fn sri_checksum(sri: &str) -> Checksum {
        Checksum::new(None, None, Some(sri)).unwrap()
    }

    /// A sha512 SRI is verified while streaming, whatever the primary digest algorithm is.
    #[tokio::test]
    async fn test_copy_and_hash_sri_sha512_ok() -> buck2_error::Result<()> {
        for config in [testing::sha1(), testing::sha256(), testing::blake3()] {
            let (_digest, bytes) = do_test(config, &sri_checksum(FOOBAR_SHA512_SRI)).await?;
            assert_eq!(std::str::from_utf8(&bytes).unwrap(), "foobar");
        }
        Ok(())
    }

    /// A flipped byte must fail with `InvalidChecksum`, not be accepted: this is the whole point
    /// of the checksum.
    #[tokio::test]
    async fn test_copy_and_hash_sri_sha512_flipped_byte() {
        for config in [testing::sha1(), testing::sha256(), testing::blake3()] {
            assert_matches!(
                do_test(config, &sri_checksum(FOOBAZ_SHA512_SRI)).await,
                Err(HttpDownloadError::InvalidChecksum {
                    digest_kind: "sri sha512",
                    ..
                })
            );
        }
    }

    #[tokio::test]
    async fn test_copy_and_hash_sri_sha256() -> buck2_error::Result<()> {
        for config in [testing::sha1(), testing::sha256(), testing::blake3()] {
            do_test(config, &sri_checksum(FOOBAR_SHA256_SRI)).await?;
        }
        // The same sha256 digest, with a byte changed in the base64.
        assert_matches!(
            do_test(
                testing::sha256(),
                &sri_checksum("sha256-w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPA=")
            )
            .await,
            Err(HttpDownloadError::InvalidChecksum {
                digest_kind: "sri sha256",
                ..
            })
        );
        Ok(())
    }

    #[test]
    fn test_checksum_new_sri() {
        let checksum = Checksum::new(None, None, Some(FOOBAR_SHA512_SRI)).unwrap();
        assert_matches!(checksum, Checksum::Sri(..));
        // An SRI alone declares no sha1 or sha256, so the digest is not known up front.
        assert_eq!(checksum.sha1(), None);
        assert_eq!(checksum.sha256(), None);
        assert_eq!(checksum.sri().unwrap().as_str(), FOOBAR_SHA512_SRI);
        assert_eq!(checksum.sri().unwrap().algorithm(), SriAlgorithm::Sha512);

        let checksum = Checksum::new(None, None, Some(FOOBAR_SHA256_SRI)).unwrap();
        assert_eq!(checksum.sri().unwrap().algorithm(), SriAlgorithm::Sha256);
    }

    #[test]
    fn test_checksum_new_sri_refused() {
        // An algorithm that is not supported is refused by name, not as a bad digest.
        let err = Checksum::new(None, None, Some("md5-rL0Y20zC+Fzt72VPzMSk2A=="))
            .unwrap_err()
            .to_string();
        assert!(err.contains("Unsupported hash algorithm `md5`"), "{err}");
        let err = Checksum::new(None, None, Some("sha384-abc="))
            .unwrap_err()
            .to_string();
        assert!(err.contains("Unsupported hash algorithm `sha384`"), "{err}");

        // Malformed tokens.
        for bad in [
            "sha512",
            "sha512-",
            "sha512-not base64!",
            // A sha256 digest labelled sha512.
            "sha512-w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=",
        ] {
            let err = Checksum::new(None, None, Some(bad))
                .unwrap_err()
                .to_string();
            assert!(err.contains("Invalid `sri` argument"), "{bad}: {err}");
        }

        // Mixing is ambiguous.
        let err = Checksum::new(
            Some("8843d7f92416211de9ebb963ff4ce28125932878"),
            None,
            Some(FOOBAR_SHA512_SRI),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot be combined"), "{err}");
    }

    /// Without `sri`, `Checksum::new` is what it was: sha1 and sha256 are accepted, alone or
    /// together, and nothing at all is refused.
    #[test]
    fn test_checksum_new_without_sri_unchanged() {
        let sha1 = "8843d7f92416211de9ebb963ff4ce28125932878";
        let sha256 = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";

        let checksum = Checksum::new(Some(sha1), None, None).unwrap();
        assert_matches!(checksum, Checksum::Sha1(..));
        assert_eq!(checksum.sha1(), Some(sha1));
        assert_eq!(checksum.sha256(), None);
        assert_eq!(checksum.sri(), None);

        let checksum = Checksum::new(None, Some(sha256), None).unwrap();
        assert_matches!(checksum, Checksum::Sha256(..));
        assert_eq!(checksum.sha256(), Some(sha256));

        let checksum = Checksum::new(Some(sha1), Some(sha256), None).unwrap();
        assert_matches!(checksum, Checksum::Both { .. });
        assert_eq!(checksum.sha1(), Some(sha1));
        assert_eq!(checksum.sha256(), Some(sha256));

        let err = Checksum::new(None, None, None).unwrap_err().to_string();
        assert!(err.contains("at least one checksum"), "{err}");
        assert!(Checksum::new(Some("abc"), None, None).is_err());
    }

    #[test]
    fn test_debug_buffer() {
        let mut buff = DebugBuffer::new(10);
        buff.peek(b"foo");
        assert_eq!(buff.to_utf8(), Some("foo"));

        let mut buff = DebugBuffer::new(2);
        buff.peek(b"foo");
        assert_eq!(buff.to_utf8(), Some("fo"));

        let mut buff = DebugBuffer::new(4);
        buff.peek(b"foo");
        buff.peek(b"foo");
        assert_eq!(buff.to_utf8(), Some("foof"));

        // 75% fine.
        let mut buff = DebugBuffer::new(4);
        buff.peek(b"foo");
        buff.peek(&[0xff]);
        assert_eq!(buff.to_utf8(), Some("foo"));

        // 50% fine.
        let mut buff = DebugBuffer::new(4);
        buff.peek(b"fo");
        buff.peek(&[0xff]);
        assert_eq!(buff.to_utf8(), Some("fo"));

        // 25% fine.
        let mut buff = DebugBuffer::new(4);
        buff.peek(b"f");
        buff.peek(&[0xff]);
        assert_eq!(buff.to_utf8(), None);

        // 0% fine.
        let mut buff = DebugBuffer::new(4);
        buff.peek(&[0xff]);
        assert_eq!(buff.to_utf8(), None);
    }
}
