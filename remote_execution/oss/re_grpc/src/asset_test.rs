/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

//! Tests of the Remote Asset client calls against a fake Remote Asset server on a loopback port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use buck2_re_configuration::Buck2OssReConfiguration;
use re_grpc_proto::build::bazel::remote::asset::v1::FetchBlobRequest;
use re_grpc_proto::build::bazel::remote::asset::v1::FetchBlobResponse;
use re_grpc_proto::build::bazel::remote::asset::v1::FetchDirectoryRequest;
use re_grpc_proto::build::bazel::remote::asset::v1::FetchDirectoryResponse;
use re_grpc_proto::build::bazel::remote::asset::v1::PushBlobRequest;
use re_grpc_proto::build::bazel::remote::asset::v1::PushBlobResponse;
use re_grpc_proto::build::bazel::remote::asset::v1::PushDirectoryRequest;
use re_grpc_proto::build::bazel::remote::asset::v1::PushDirectoryResponse;
use re_grpc_proto::build::bazel::remote::asset::v1::fetch_server::Fetch;
use re_grpc_proto::build::bazel::remote::asset::v1::fetch_server::FetchServer;
use re_grpc_proto::build::bazel::remote::asset::v1::push_server::Push;
use re_grpc_proto::build::bazel::remote::asset::v1::push_server::PushServer;
use re_grpc_proto::build::bazel::remote::execution::v2::Digest;
use re_grpc_proto::google::rpc::Status as RpcStatus;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Server;

use crate::REClient;
use crate::REClientBuilder;
use crate::RemoteExecutionMetadata;
use crate::TDigest;

const URL: &str = "https://example.invalid/pkg-1.0.tgz";
const SRI: &str = "sha512-WS0ODr4Iq4dQLwdFx4MbA+FjkAM3Lh7JpQ6sPnHpbyfsTTDBbQ+4JrDLAobY/uZXC2xNVj4Kh9r2Ztj0xLuLgQ==";
const HASH: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

/// What the fake answers to `FetchBlob`.
#[derive(Clone, Copy)]
enum FetchScript {
    Hit,
    /// `NOT_FOUND` as the RPC status.
    MissRpc,
    /// `NOT_FOUND` inside the response, as the Remote Asset spec describes.
    MissInBody,
    /// A failure that is not a miss.
    Denied,
}

#[derive(Default)]
struct Recorded {
    fetches: Vec<FetchBlobRequest>,
    pushes: Vec<PushBlobRequest>,
}

struct FakeAsset {
    script: FetchScript,
    recorded: Mutex<Recorded>,
}

#[tonic::async_trait]
impl Fetch for FakeAsset {
    async fn fetch_blob(
        &self,
        request: Request<FetchBlobRequest>,
    ) -> Result<Response<FetchBlobResponse>, Status> {
        self.recorded
            .lock()
            .unwrap()
            .fetches
            .push(request.into_inner());
        match self.script {
            FetchScript::Hit => Ok(Response::new(FetchBlobResponse {
                blob_digest: Some(Digest {
                    hash: HASH.to_owned(),
                    size_bytes: 5,
                }),
                ..Default::default()
            })),
            FetchScript::MissRpc => Err(Status::not_found("no such asset")),
            FetchScript::MissInBody => Ok(Response::new(FetchBlobResponse {
                status: Some(RpcStatus {
                    code: 5,
                    message: "no such asset".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            FetchScript::Denied => Err(Status::permission_denied("nope")),
        }
    }

    async fn fetch_directory(
        &self,
        _request: Request<FetchDirectoryRequest>,
    ) -> Result<Response<FetchDirectoryResponse>, Status> {
        Err(Status::unimplemented("FetchDirectory"))
    }
}

#[tonic::async_trait]
impl Push for FakeAsset {
    async fn push_blob(
        &self,
        request: Request<PushBlobRequest>,
    ) -> Result<Response<PushBlobResponse>, Status> {
        self.recorded
            .lock()
            .unwrap()
            .pushes
            .push(request.into_inner());
        Ok(Response::new(PushBlobResponse {}))
    }

    async fn push_directory(
        &self,
        _request: Request<PushDirectoryRequest>,
    ) -> Result<Response<PushDirectoryResponse>, Status> {
        Err(Status::unimplemented("PushDirectory"))
    }
}

async fn start(script: FetchScript) -> (REClient, Arc<FakeAsset>) {
    let fake = Arc::new(FakeAsset {
        script,
        recorded: Mutex::new(Recorded::default()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = Server::builder()
        .add_service(FetchServer::from_arc(fake.clone()))
        .add_service(PushServer::from_arc(fake.clone()));
    tokio::spawn(async move {
        server
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let address = format!("grpc://{addr}");
    let client = REClientBuilder::build_and_connect(&Buck2OssReConfiguration {
        cas_address: Some(address.clone()),
        engine_address: Some(address.clone()),
        action_cache_address: Some(address),
        capabilities: Some(false),
        ..Default::default()
    })
    .await
    .unwrap();
    (client, fake)
}

fn digest() -> TDigest {
    TDigest {
        hash: HASH.to_owned(),
        size_in_bytes: 5,
        ..Default::default()
    }
}

/// A hit hands back the server's digest, and the request names the URL, carries the sri in a
/// `checksum.sri` qualifier, and asks for SHA256 explicitly rather than relying on the default
/// (a server that guesses a different function would return a digest the CAS cannot resolve).
#[tokio::test]
async fn fetch_hit_sends_sri_qualifier_and_sha256() {
    let (client, fake) = start(FetchScript::Hit).await;

    let found = client
        .fetch_blob_by_sri(&RemoteExecutionMetadata::default(), URL, SRI)
        .await
        .unwrap();
    assert_eq!(found, Some(digest()));

    let recorded = fake.recorded.lock().unwrap();
    assert_eq!(recorded.fetches.len(), 1);
    let request = &recorded.fetches[0];
    assert_eq!(request.uris, vec![URL.to_owned()]);
    assert_eq!(request.qualifiers.len(), 1);
    assert_eq!(request.qualifiers[0].name, "checksum.sri");
    assert_eq!(request.qualifiers[0].value, SRI);
    // `DigestFunction.Value.SHA256`.
    assert_eq!(request.digest_function, 1);
}

/// A miss is `Ok(None)` whether the server reports it as the RPC status or in the response, so
/// the caller downloads over HTTP instead of failing.
#[tokio::test]
async fn fetch_not_found_is_a_miss() {
    for script in [FetchScript::MissRpc, FetchScript::MissInBody] {
        let (client, _fake) = start(script).await;
        let found = client
            .fetch_blob_by_sri(&RemoteExecutionMetadata::default(), URL, SRI)
            .await
            .unwrap();
        assert_eq!(found, None);
    }
}

/// Any other failure is an error the caller can see, not a silent miss.
#[tokio::test]
async fn fetch_other_failure_is_an_error() {
    let (client, _fake) = start(FetchScript::Denied).await;
    let result = client
        .fetch_blob_by_sri(&RemoteExecutionMetadata::default(), URL, SRI)
        .await;
    assert!(result.is_err());
}

/// The push names the URL, the sri qualifier, the blob digest and the digest function.
#[tokio::test]
async fn push_sends_digest_and_sri() {
    let (client, fake) = start(FetchScript::Hit).await;

    client
        .push_blob_by_sri(&RemoteExecutionMetadata::default(), URL, SRI, &digest())
        .await
        .unwrap();

    let recorded = fake.recorded.lock().unwrap();
    assert_eq!(recorded.pushes.len(), 1);
    let request = &recorded.pushes[0];
    assert_eq!(request.uris, vec![URL.to_owned()]);
    assert_eq!(request.qualifiers.len(), 1);
    assert_eq!(request.qualifiers[0].name, "checksum.sri");
    assert_eq!(request.qualifiers[0].value, SRI);
    assert_eq!(
        request.blob_digest,
        Some(Digest {
            hash: HASH.to_owned(),
            size_bytes: 5,
        })
    );
    assert_eq!(request.digest_function, 1);
}
