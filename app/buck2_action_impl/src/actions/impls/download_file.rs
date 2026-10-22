/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use allocative::Allocative;
use async_trait::async_trait;
use buck2_artifact::artifact::build_artifact::BuildArtifact;
use buck2_build_api::actions::Action;
use buck2_build_api::actions::ActionExecutionCtx;
use buck2_build_api::actions::UnregisteredAction;
use buck2_build_api::actions::errors::execute_error::ExecuteError;
use buck2_build_api::actions::execute::action_executor::ActionExecutionKind;
use buck2_build_api::actions::execute::action_executor::ActionExecutionMetadata;
use buck2_build_api::actions::execute::action_executor::ActionOutputs;
use buck2_build_api::artifact_groups::ArtifactGroup;
use buck2_build_signals::env::WaitingData;
use buck2_common::cas_digest::CasDigestConfig;
use buck2_common::cas_digest::RawDigest;
use buck2_common::file_ops::metadata::FileDigest;
use buck2_common::file_ops::metadata::FileMetadata;
use buck2_common::file_ops::metadata::TrackedFileDigest;
use buck2_common::io::trace::TracingIoProvider;
use buck2_core::category::CategoryRef;
use buck2_core::fs::buck_out_path::BuildArtifactPath;
use buck2_core::fs::project_rel_path::ProjectRelativePathBuf;
use buck2_error::BuckErrorContext;
use buck2_error::BuckErrorOptionContext;
use buck2_error::ErrorTag;
use buck2_error::buck2_error;
use buck2_error::conversion::from_any_with_tag;
use buck2_execute::artifact_value::ArtifactValue;
use buck2_execute::digest::CasDigestToReExt;
use buck2_execute::digest_config::DigestConfig;
use buck2_execute::execute::clean_output_paths::CleanOutputPaths;
use buck2_execute::execute::command_executor::ActionExecutionTimingData;
use buck2_execute::materialize::http::Checksum;
use buck2_execute::materialize::http::ChecksumKey;
use buck2_execute::materialize::http::http_download;
use buck2_execute::materialize::http::http_head;
use buck2_execute::materialize::materializer::CasDownloadInfo;
use buck2_execute::materialize::materializer::DeclareArtifactPayload;
use buck2_execute::materialize::materializer::DeclareMatchOutcome;
use buck2_execute::re::manager::ManagedRemoteExecutionClient;
use buck2_execute::re::presence::NegativeCache;
use buck2_hash::BuckIndexSet;
use buck2_http::HttpClient;
use dupe::Dupe;
use pagable::Pagable;
use pagable::pagable_typetag;
use remote_execution::NamedDigest;
use remote_execution::TDigest;
use starlark::values::OwnedFrozen;
use starlark::values::Value;

use crate::actions::impls::download_file_alias;
use crate::actions::impls::download_file_alias::ChecksumAliases;
use crate::actions::impls::download_file_alias::RemoteAsset;
use crate::actions::impls::download_file_alias::Resolved;
use crate::actions::impls::offline;

#[derive(Debug, buck2_error::Error)]
#[buck2(tag = Input)]
enum DownloadFileActionError {
    #[error("Exactly one output file must be specified for a download file action, got {0}")]
    WrongNumberOfOutputs(usize),
    #[error(
        "Downloads using content-based path {0} must supply metadata (usually in the form of a sha1)!"
    )]
    ContentBasedPathWithoutMetadata(BuildArtifactPath),
}

/// The size a download must have: the declared metadata's, else `size_bytes`. The metadata's size
/// is `size_bytes` when that was given, so `size_bytes` only matters when no metadata could be
/// declared (for example a sha512-only download).
fn expected_size(metadata: Option<&FileMetadata>, size_bytes: Option<u64>) -> Option<u64> {
    metadata
        .map(|metadata| metadata.digest.size())
        .or(size_bytes)
}

/// Fails if a size was declared (by `size_bytes` or a HEAD response) and the download has another.
fn check_downloaded_size(expected: Option<u64>, actual: u64) -> buck2_error::Result<()> {
    match expected {
        Some(expected) if expected != actual => Err(buck2_error!(
            ErrorTag::DownloadSizeMismatch,
            "Downloaded size ({}) does not match expected size ({})",
            actual,
            expected,
        )),
        _ => Ok(()),
    }
}

enum DeclaredMetadata {
    /// The file's digest is known without downloading it.
    Known(FileMetadata),
    /// No checksum the digest config accepts, or no size: only a download can tell.
    Unknown,
    /// The size had to come from a HEAD request, and that failed.
    HeadFailed(buck2_error::Error),
}

/// The digest the checksum names, if it names one the digest config accepts. `None` for a
/// checksum that does not (for example a `sha512` alone): that digest is not known until the file
/// is read.
fn checksum_digest(checksum: &Checksum, cas_digest_config: CasDigestConfig) -> Option<RawDigest> {
    if cas_digest_config.allows_sha1() {
        checksum
            .sha1()
            .and_then(|sha1| RawDigest::parse_sha1(sha1.as_bytes()).ok())
    } else if cas_digest_config.allows_sha256() {
        checksum
            .sha256()
            .and_then(|sha256| RawDigest::parse_sha256(sha256.as_bytes()).ok())
    } else {
        None
    }
}

/// The hash to ask a Remote Asset server about, for a file whose checksum does not give its CAS
/// digest. `None` when the checksum does give it (those downloads go to the CAS or the origin as
/// they always did) or has no hash a server can be asked about.
fn alias_key(checksum: &Checksum, cas_digest_config: CasDigestConfig) -> Option<ChecksumKey<'_>> {
    match checksum_digest(checksum, cas_digest_config) {
        Some(_) => None,
        None => checksum.lookup_key(),
    }
}

/// Whether the Remote Asset server has said it does not implement Remote Asset. Remembered for the
/// life of the daemon, whatever the RE connection: a server that lacks the API will not gain it
/// during a session, and the cost of being wrong is one origin download per file, which is what a
/// build without Remote Asset does anyway.
static REMOTE_ASSET_UNIMPLEMENTED: AtomicBool = AtomicBool::new(false);

/// A Remote Asset server and the CAS beside it, reached through the invocation's RE connection.
struct ReChecksumAliases {
    re: ManagedRemoteExecutionClient,
    /// Where the downloaded file is on disk, for the upload.
    abs_path: String,
}

#[async_trait]
impl ChecksumAliases for ReChecksumAliases {
    async fn fetch(
        &self,
        url: &str,
        key: ChecksumKey<'_>,
    ) -> buck2_error::Result<Option<FileDigest>> {
        self.re
            .fetch_blob_by_checksum(url, key.algorithm, key.hex)
            .await?
            .map(|digest| sha256_file_digest(&digest))
            .transpose()
    }

    async fn upload(&self, digest: &FileDigest) -> buck2_error::Result<()> {
        self.re
            .upload_files_and_directories(
                vec![NamedDigest {
                    name: self.abs_path.clone(),
                    digest: digest.to_re(),
                    ..Default::default()
                }],
                Vec::new(),
                Vec::new(),
            )
            .await
    }

    async fn push(
        &self,
        url: &str,
        key: ChecksumKey<'_>,
        digest: &FileDigest,
    ) -> buck2_error::Result<()> {
        self.re
            .push_blob_by_checksum(url, key.algorithm, key.hex, &digest.to_re())
            .await
    }
}

/// The digest a Remote Asset server returned, which was asked for as sha256.
fn sha256_file_digest(digest: &TDigest) -> buck2_error::Result<FileDigest> {
    let size = u64::try_from(digest.size_in_bytes).map_err(|_| {
        buck2_error!(
            ErrorTag::Input,
            "Remote Asset server returned a negative size in `{}`",
            digest
        )
    })?;
    let raw = RawDigest::parse_sha256(digest.hash.as_bytes()).map_err(|e| {
        buck2_error!(
            ErrorTag::Input,
            "Remote Asset server returned a digest that is not sha256, `{}`: {}",
            digest,
            e
        )
    })?;
    Ok(FileDigest::new(raw, size))
}

#[derive(Debug, Allocative, Pagable)]
pub(crate) struct UnregisteredDownloadFileAction {
    checksum: Checksum,
    size_bytes: Option<u64>,
    url: Arc<str>,
    vpnless_url: Option<Arc<str>>,
    is_executable: bool,
}

impl UnregisteredDownloadFileAction {
    pub(crate) fn new(
        checksum: Checksum,
        size_bytes: Option<u64>,
        url: Arc<str>,
        vpnless_url: Option<Arc<str>>,
        is_executable: bool,
    ) -> Self {
        Self {
            checksum,
            size_bytes,
            url,
            vpnless_url,
            is_executable,
        }
    }
}

impl UnregisteredAction for UnregisteredDownloadFileAction {
    fn register(
        self: Box<Self>,
        outputs: BuckIndexSet<BuildArtifact>,
        _starlark_data: Option<OwnedFrozen<Value<'static>>>,
        _error_handler: Option<OwnedFrozen<Value<'static>>>,
    ) -> buck2_error::Result<Box<dyn Action>> {
        Ok(Box::new(DownloadFileAction::new(outputs, *self)?))
    }
}

#[derive(Debug, Allocative, Pagable)]
struct DownloadFileAction {
    outputs: Box<[BuildArtifact]>,
    inner: UnregisteredDownloadFileAction,
}

impl DownloadFileAction {
    fn new(
        outputs: BuckIndexSet<BuildArtifact>,
        inner: UnregisteredDownloadFileAction,
    ) -> buck2_error::Result<Self> {
        if outputs.len() != 1 {
            Err(DownloadFileActionError::WrongNumberOfOutputs(outputs.len()).into())
        } else {
            Ok(Self {
                outputs: outputs.into_iter().collect(),
                inner,
            })
        }
    }

    fn output(&self) -> &BuildArtifact {
        self.outputs
            .iter()
            .next()
            .expect("a single artifact by construction")
    }

    fn url(&self, client: &HttpClient) -> &Arc<str> {
        if client.supports_vpnless() {
            self.inner.vpnless_url.as_ref().unwrap_or(&self.inner.url)
        } else {
            &self.inner.url
        }
    }

    /// Works out what the downloaded file's metadata will be without downloading it.
    async fn declared_metadata(
        &self,
        client: &HttpClient,
        digest_config: DigestConfig,
    ) -> DeclaredMetadata {
        let digest = match checksum_digest(&self.inner.checksum, digest_config.cas_digest_config())
        {
            Some(digest) => digest,
            None => return DeclaredMetadata::Unknown,
        };

        let size = match self.inner.size_bytes {
            Some(s) => Some(s),
            None => match self.head_content_length(client).await {
                Ok(size) => size,
                Err(e) => return DeclaredMetadata::HeadFailed(e),
            },
        };

        match size {
            Some(size) => {
                let digest = TrackedFileDigest::new(
                    FileDigest::new(digest, size),
                    digest_config.cas_digest_config(),
                );
                DeclaredMetadata::Known(FileMetadata {
                    digest,
                    is_executable: self.inner.is_executable,
                })
            }
            None => DeclaredMetadata::Unknown,
        }
    }

    /// The `Content-Length` a HEAD request reports for the URL, if the server sends one.
    async fn head_content_length(&self, client: &HttpClient) -> buck2_error::Result<Option<u64>> {
        let url = self.url(client);
        let head = http_head(client, url)
            .await
            .map_err(|e| e.tag([ErrorTag::DownloadFileHeadRequest]))?;

        head.headers()
            .get(http::header::CONTENT_LENGTH)
            .map(|content_length| {
                let content_length = content_length
                    .to_str()
                    .map_err(|e| from_any_with_tag(e, buck2_error::ErrorTag::Http))
                    .buck_error_context("Header is not valid utf-8")?;
                let content_length_number =
                    content_length.parse().with_buck_error_context(|| {
                        format!("Header is not a number: `{content_length}`")
                    })?;
                buck2_error::Ok(content_length_number)
            })
            .transpose()
            .with_buck_error_context(|| {
                format!(
                    "Request to `{}` returned an invalid `{}` header",
                    url,
                    http::header::CONTENT_LENGTH
                )
            })
    }

    fn output_path(
        &self,
        ctx: &dyn ActionExecutionCtx,
        value: &ArtifactValue,
    ) -> buck2_error::Result<ProjectRelativePathBuf> {
        let path = self.output().get_path();
        ctx.fs().resolve_build(
            path,
            path.is_content_based_path()
                .then(|| value.content_based_path_hash())
                .as_ref(),
        )
    }

    /// Declares the output as a CAS download when the CAS already holds the content, which
    /// leaves nothing to fetch from the origin server or to write to disk now. `None` when the
    /// content is not there, is about to expire, or there is no CAS to ask.
    async fn declare_from_cas(
        &self,
        ctx: &dyn ActionExecutionCtx,
        metadata: &FileMetadata,
    ) -> buck2_error::Result<Option<ArtifactValue>> {
        if !ctx.cas_configured() {
            return Ok(None);
        }
        let use_case = ctx.invocation_re_use_case();
        let info = Arc::new(CasDownloadInfo::new_probed(use_case));
        let digest = metadata.digest.data();

        // The CAS reports every digest of size 0 as present, so the probe cannot tell a checksum
        // declared with a size of 0 apart from the empty file. Only the download can.
        if digest.size() == 0
            && !ctx
                .digest_config()
                .cas_digest_config()
                .is_empty_digest(digest)
        {
            return Ok(None);
        }

        // A stale miss only costs the download that would otherwise have been skipped.
        let expiration = match ctx
            .re_client()
            .with_use_case(use_case)
            .check_presence(vec![metadata.digest.dupe()], NegativeCache::Allowed, &info)
            .await
        {
            Ok(presence) => match presence.into_iter().next().flatten() {
                Some(expiration) => expiration,
                None => return Ok(None),
            },
            Err(e) => {
                // Falling back to the download is correct for this action, but a CAS that cannot
                // answer this query would silently turn every download into an origin fetch,
                // which should be visible somewhere.
                let _ignored = buck2_core::soft_error!(
                    "download_file_cas_probe_failed",
                    e.context(format!("CAS lookup for `{digest}` failed; downloading instead")),
                    quiet: true
                );
                return Ok(None);
            }
        };

        let value = ArtifactValue::file(FileMetadata {
            digest: TrackedFileDigest::new_expires(
                digest.dupe(),
                expiration,
                ctx.digest_config().cas_digest_config(),
            ),
            is_executable: metadata.is_executable,
        });
        let path = self.output_path(ctx, &value)?;
        ctx.materializer()
            .declare_cas_many(
                info,
                vec![DeclareArtifactPayload {
                    path,
                    artifact: value.dupe(),
                }],
            )
            .await?;

        Ok(Some(value))
    }

    /// Puts the content at the output path now, unless the materializer already has exactly this
    /// content there from an earlier daemon.
    async fn download(
        &self,
        ctx: &dyn ActionExecutionCtx,
        client: &HttpClient,
        url: &str,
        metadata: Option<&FileMetadata>,
    ) -> buck2_error::Result<(ArtifactValue, ActionExecutionKind)> {
        let materializer = ctx.materializer();

        let path = match metadata {
            Some(metadata) => {
                let value = ArtifactValue::file(metadata.dupe());
                let path = self.output_path(ctx, &value)?;
                if let DeclareMatchOutcome::Match = materializer
                    .declare_match(vec![(path.clone(), value.dupe())])
                    .await?
                {
                    return Ok((value, ActionExecutionKind::Simple));
                }
                path
            }
            None => ctx.fs().resolve_build(self.output().get_path(), None)?,
        };

        // Whatever is at the path is stale or untracked; the `declare_existing` below replaces
        // the materializer's record of it, so the disk has to be cleared to match. The lease is
        // held until that report is in.
        let output_lease = materializer.prepare_outputs(vec![path.clone()]).await?;
        ctx.blocking_executor()
            .execute_io(
                Box::new(CleanOutputPaths {
                    paths: vec![path.clone()],
                }),
                ctx.cancellation_context(),
            )
            .await?;

        let digest = http_download(
            client,
            ctx.fs().fs(),
            ctx.digest_config(),
            &path,
            url,
            &self.inner.checksum,
            self.inner.is_executable,
        )
        .await?;

        // RE knows this file by the digest (checksum, size), where the size came from
        // `size_bytes` or the HEAD response rather than from the content. A wrong size would leave
        // every remote consumer unable to find its input, so it is caught here. `size_bytes` is
        // checked even when no digest could be declared up front (for example a sha512-only
        // download), where it is the only thing that can catch a wrong size.
        check_downloaded_size(
            expected_size(metadata, self.inner.size_bytes),
            digest.size(),
        )?;

        // The declared metadata, when there is any, is the value: the checksum verified the
        // content and the size was checked above, and a content-based output path was resolved
        // from it. The digest the download computed is under the digest config's preferred
        // algorithm, which need not be the checksum's, so it only stands in when nothing was
        // declared.
        let value = match metadata {
            Some(metadata) => ArtifactValue::file(metadata.dupe()),
            None => ArtifactValue::file(FileMetadata {
                digest,
                is_executable: self.inner.is_executable,
            }),
        };
        materializer
            .declare_existing(
                &output_lease,
                vec![DeclareArtifactPayload {
                    path,
                    artifact: value.dupe(),
                }],
            )
            .await?;

        Ok((value, ActionExecutionKind::Simple))
    }

    /// Gets a file whose checksum does not give its CAS digest. A Remote Asset server, when remote
    /// execution is configured, may know which CAS blob has the content behind `key`, in which case
    /// it is declared from the CAS without downloading it; otherwise it is downloaded, and then
    /// recorded with the server.
    async fn download_with_alias(
        &self,
        ctx: &dyn ActionExecutionCtx,
        client: &HttpClient,
        url: &str,
        key: ChecksumKey<'_>,
    ) -> buck2_error::Result<(ArtifactValue, ActionExecutionKind)> {
        let aliases = if download_file_alias::aliases_usable(
            ctx.cas_configured(),
            ctx.digest_config().cas_digest_config(),
        ) {
            let path = ctx.fs().resolve_build(self.output().get_path(), None)?;
            Some(ReChecksumAliases {
                re: ctx.re_client().with_use_case(ctx.invocation_re_use_case()),
                abs_path: ctx.fs().fs().resolve(&path).to_string(),
            })
        } else {
            None
        };

        let remote = aliases.as_ref().map(|aliases| RemoteAsset {
            aliases: aliases as &dyn ChecksumAliases,
            unimplemented: &REMOTE_ASSET_UNIMPLEMENTED,
            deadlines: download_file_alias::DEADLINES,
        });

        let resolved = download_file_alias::resolve(
            remote.as_ref(),
            url,
            key,
            self.inner.size_bytes,
            |digest| async move {
                let metadata = FileMetadata {
                    digest: TrackedFileDigest::new(digest, ctx.digest_config().cas_digest_config()),
                    is_executable: self.inner.is_executable,
                };
                self.declare_from_cas(ctx, &metadata).await
            },
            || async move {
                let (value, _) = self.download(ctx, client, url, None).await?;
                let digest = value
                    .digest()
                    .internal_error("A downloaded file has a digest")?
                    .clone();
                Ok((value, digest))
            },
        )
        .await?;

        Ok(match resolved {
            Resolved::FromCas(value) => (value, ActionExecutionKind::Deferred),
            Resolved::Downloaded(value) => (value, ActionExecutionKind::Simple),
        })
    }

    /// Execute this action for offline builds (e.g. no network).
    async fn execute_for_offline(
        &self,
        ctx: &mut dyn ActionExecutionCtx,
    ) -> buck2_error::Result<(ActionOutputs, ActionExecutionMetadata)> {
        let outputs = offline::declare_copy_from_offline_cache(ctx, &[self.output()]).await?;

        Ok((
            outputs,
            ActionExecutionMetadata {
                dep_file_db_writes_queued: 0,
                execution_kind: ActionExecutionKind::Simple,
                timing: ActionExecutionTimingData::default(),
                input_files_bytes: None,
                waiting_data: WaitingData::new(),
            },
        ))
    }
}

#[pagable_typetag]
#[async_trait]
impl Action for DownloadFileAction {
    fn kind(&self) -> buck2_data::ActionKind {
        buck2_data::ActionKind::DownloadFile
    }

    fn inputs(&self) -> buck2_error::Result<Cow<'_, [ArtifactGroup]>> {
        Ok(Cow::Borrowed(&[]))
    }

    fn outputs(&self) -> Cow<'_, [BuildArtifact]> {
        Cow::Borrowed(&self.outputs)
    }

    fn first_output(&self) -> &BuildArtifact {
        self.output()
    }

    fn category(&self) -> CategoryRef<'_> {
        CategoryRef::unchecked_new("download_file")
    }

    fn identifier(&self) -> Option<&str> {
        self.outputs
            .iter()
            .next()
            .map(|o| o.get_path().path().as_str())
    }

    async fn execute(
        &self,
        ctx: &mut dyn ActionExecutionCtx,
        waiting_data: WaitingData,
    ) -> Result<(ActionOutputs, ActionExecutionMetadata), ExecuteError> {
        // Early return - if this path exists, it's because we're running in a
        // special offline mode where the HEAD request below will likely fail.
        // Shortcut and just return this path as the action output.
        //
        // This mostly looks like a "copy" action.
        if ctx.run_action_knobs().use_network_action_output_cache {
            return self.execute_for_offline(ctx).await.map_err(Into::into);
        }

        let client = ctx.http_client();
        let url = self.url(client);
        let is_content_based = self.output().get_path().is_content_based_path();

        let metadata = match self.declared_metadata(client, ctx.digest_config()).await {
            DeclaredMetadata::Known(metadata) => Some(metadata),
            DeclaredMetadata::Unknown => None,
            DeclaredMetadata::HeadFailed(e) => {
                if is_content_based {
                    return Err(e.into());
                }
                // Not a soft error: servers legitimately refuse HEAD, and a server that is
                // actually down fails the GET that follows.
                tracing::debug!(
                    "HEAD request for `{}` failed, downloading instead: {:#}",
                    url,
                    e
                );
                None
            }
        };
        if metadata.is_none() && is_content_based {
            return Err(ExecuteError::Error {
                error: DownloadFileActionError::ContentBasedPathWithoutMetadata(
                    self.output().get_path().dupe(),
                )
                .into(),
            });
        }

        let (value, execution_kind) = match &metadata {
            Some(metadata) => match self.declare_from_cas(ctx, metadata).await? {
                Some(value) => (value, ActionExecutionKind::Deferred),
                None => self.download(ctx, client, url, Some(metadata)).await?,
            },
            None => {
                // The checksum does not give the CAS digest, so the CAS cannot be asked for the
                // file directly. A Remote Asset server may know it by a hash the checksum has.
                let digest_config = ctx.digest_config().cas_digest_config();
                match alias_key(&self.inner.checksum, digest_config) {
                    Some(key) => self.download_with_alias(ctx, client, url, key).await?,
                    None => self.download(ctx, client, url, None).await?,
                }
            }
        };

        // If we're tracing I/O, get the materializer to copy to the offline cache
        // so we can include it in the offline archive manifest later.
        let io_provider = ctx.io_provider();
        if let Some(tracer) = TracingIoProvider::from_io(io_provider) {
            offline::declare_copy_to_offline_output_cache(ctx, tracer, self.output(), value.dupe())
                .await?;
        }

        Ok((
            ActionOutputs::from_single(self.output().get_path().dupe(), value),
            ActionExecutionMetadata {
                dep_file_db_writes_queued: 0,
                execution_kind,
                timing: ActionExecutionTimingData::default(),
                input_files_bytes: None,
                waiting_data,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use buck2_common::cas_digest::testing;

    use super::*;

    // TODO: This needs proper tests, but right now it's kind of a pain to get the
    //       action framework up and running to test actions
    #[test]
    fn downloads_file() {}

    const SHA1: &str = "8843d7f92416211de9ebb963ff4ce28125932878";
    const SHA256: &str = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";
    const SHA512: &str = "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425";

    /// `sha1` and `sha256` declare the digest as they always did. Catches a change to which one
    /// wins or to which the digest config accepts, since that decides what the CAS is asked for.
    #[test]
    fn sha1_and_sha256_checksums_declare_a_digest() {
        let sha1 = Checksum::new([("sha1", SHA1)]).unwrap();
        let sha256 = Checksum::new([("sha256", SHA256)]).unwrap();
        let both = Checksum::new([("sha1", SHA1), ("sha256", SHA256)]).unwrap();

        assert_matches!(
            checksum_digest(&sha1, testing::sha1()),
            Some(RawDigest::Sha1(..))
        );
        assert_matches!(
            checksum_digest(&sha256, testing::sha256()),
            Some(RawDigest::Sha256(..))
        );
        // When both are accepted, the one that is listed as the 160-bit digest wins.
        assert_matches!(
            checksum_digest(&both, testing::sha1_sha256()),
            Some(RawDigest::Sha1(..))
        );
        assert_matches!(
            checksum_digest(&both, testing::sha256()),
            Some(RawDigest::Sha256(..))
        );
        // A checksum the config does not accept declares nothing.
        assert_matches!(checksum_digest(&sha256, testing::sha1()), None);
        assert_matches!(checksum_digest(&sha1, testing::sha256()), None);
    }

    /// A `sha512` alone declares no digest, whatever the config accepts, so the action downloads
    /// the file to learn it (or asks a Remote Asset server). Catches a sha512 that is mistaken for
    /// a CAS digest.
    #[test]
    fn sha512_checksum_declares_no_digest() {
        let sha512 = Checksum::new([("sha512", SHA512)]).unwrap();
        for config in [
            testing::sha1(),
            testing::sha256(),
            testing::sha1_sha256(),
            testing::blake3(),
        ] {
            assert_matches!(checksum_digest(&sha512, config), None);
        }
    }

    /// Remote Asset is asked about a file only when its checksum gives no CAS digest and has a hash
    /// the server can be asked about. Catches a lookup (and with it an upload and a push) for a
    /// download that works without one, which would change what existing callers do.
    #[test]
    fn remote_asset_is_asked_only_when_the_checksum_gives_no_digest() {
        let sha1 = Checksum::new([("sha1", SHA1)]).unwrap();
        let sha256 = Checksum::new([("sha256", SHA256)]).unwrap();
        let sha512 = Checksum::new([("sha512", SHA512)]).unwrap();
        let sha1_512 = Checksum::new([("sha1", SHA1), ("sha512", SHA512)]).unwrap();
        let key =
            |checksum: &Checksum, config| alias_key(checksum, config).map(|key| key.algorithm);

        assert_eq!(key(&sha512, testing::sha256()), Some("sha512"));
        // The sha1 gives the digest under a sha1 config; under a sha256 one it does not, and the
        // sha512 is what the server is asked about (never the sha1).
        assert_eq!(key(&sha1_512, testing::sha1()), None);
        assert_eq!(key(&sha1_512, testing::sha256()), Some("sha512"));
        // Existing callers: the digest is given, or there is nothing to ask a server with.
        assert_eq!(key(&sha256, testing::sha256()), None);
        assert_eq!(key(&sha1, testing::sha1()), None);
        assert_eq!(key(&sha1, testing::sha256()), None);
    }

    #[test]
    fn remote_asset_digest_is_parsed_as_sha256() {
        let digest = sha256_file_digest(&TDigest {
            hash: SHA256.to_owned(),
            size_in_bytes: 6,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(digest.size(), 6);
        assert_eq!(digest.raw_digest().to_string(), SHA256);

        // A digest of another function, or without a usable size, is an error and so a miss.
        assert!(
            sha256_file_digest(&TDigest {
                hash: SHA1.to_owned(),
                size_in_bytes: 6,
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            sha256_file_digest(&TDigest {
                hash: SHA256.to_owned(),
                size_in_bytes: -1,
                ..Default::default()
            })
            .is_err()
        );
    #[test]
    fn test_check_downloaded_size() {
        // Defect: `size_bytes` ignored when the checksum alone cannot name a CAS digest (a
        // sha512-only download). Mutant: the comparison removed.
        let err = check_downloaded_size(Some(6), 7).unwrap_err();
        assert!(err.has_tag(ErrorTag::DownloadSizeMismatch));
        assert!(
            format!("{err:#}").contains("Downloaded size (7) does not match expected size (6)")
        );

        // Defect: refusing a download whose size is right, or one that declared no size.
        // Mutant: `expected != actual` turned into `expected == actual`, or `_ => Ok(())` turned
        // into an error.
        check_downloaded_size(Some(6), 6).unwrap();
        check_downloaded_size(None, 6).unwrap();
    }

    #[test]
    fn test_expected_size() {
        // A sha512-only download has no metadata; `size_bytes` is the only size there is.
        // Mutant: `.or(size_bytes)` removed.
        assert_eq!(expected_size(None, Some(6)), Some(6));
        assert_eq!(expected_size(None, None), None);

        // With metadata, its size wins (it is `size_bytes` or the HEAD response's).
        // Mutant: the two sources swapped.
        let metadata = FileMetadata {
            digest: TrackedFileDigest::new(
                FileDigest::from_content(b"foobar", testing::sha256()),
                testing::sha256(),
            ),
            is_executable: false,
        };
        assert_eq!(expected_size(Some(&metadata), Some(9)), Some(6));
        assert_eq!(expected_size(Some(&metadata), None), Some(6));
    }
}
