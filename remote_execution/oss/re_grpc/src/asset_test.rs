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
const SHA512_HEX: &str = "592d0e0ebe08ab87502f0745c7831b03e1639003372e1ec9a50eac3e71e96f27ec4d30c16d0fb826b0cb0286d8fee6570b6c4d563e0a87daf666d8f4c4bb8b81";
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
    /// The server cannot be reached right now.
    Unavailable,
    /// The server does not implement Remote Asset.
    Unimplemented,
    /// A digest, with the digest function the response says it was computed with.
    HitWithFunction(i32),
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
            FetchScript::Unavailable => Err(Status::unavailable("busy")),
            FetchScript::Unimplemented => Err(Status::unimplemented("Fetch")),
            FetchScript::HitWithFunction(function) => Ok(Response::new(FetchBlobResponse {
                blob_digest: Some(Digest {
                    hash: HASH.to_owned(),
                    size_bytes: 5,
                }),
                digest_function: function,
                ..Default::default()
            })),
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

/// A hit hands back the server's digest, and the request names the URL, carries the hash in a
/// `checksum.sri` qualifier in the standard SRI form (algorithm, a dash, base64 of the raw bytes,
/// although the caller passed hex), and asks for SHA256 explicitly rather than relying on the default
/// (a server that guesses a different function would return a digest the CAS cannot resolve).
#[tokio::test]
async fn fetch_hit_sends_checksum_qualifier_and_sha256() {
    let (client, fake) = start(FetchScript::Hit).await;

    let found = client
        .fetch_blob_by_checksum(
            &RemoteExecutionMetadata::default(),
            URL,
            "sha512",
            SHA512_HEX,
        )
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
            .fetch_blob_by_checksum(
                &RemoteExecutionMetadata::default(),
                URL,
                "sha512",
                SHA512_HEX,
            )
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
        .fetch_blob_by_checksum(
            &RemoteExecutionMetadata::default(),
            URL,
            "sha512",
            SHA512_HEX,
        )
        .await;
    assert!(result.is_err());
}

/// The push names the URL, the checksum qualifier, the blob digest and the digest function.
#[tokio::test]
async fn push_sends_digest_and_checksum() {
    let (client, fake) = start(FetchScript::Hit).await;

    client
        .push_blob_by_checksum(
            &RemoteExecutionMetadata::default(),
            URL,
            "sha512",
            SHA512_HEX,
            &digest(),
        )
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

/// A response that says its digest is of another function than the one asked for is a miss: the
/// digest would name nothing in a SHA256 CAS. One that says SHA256 is a hit, and so is one that
/// says nothing (the spec reads that as SHA256).
#[tokio::test]
async fn fetch_hit_of_another_digest_function_is_a_miss() {
    // `DigestFunction.Value`: SHA256 = 1, SHA1 = 2, SHA512 = 4, BLAKE3 = 9.
    for (function, hit) in [(0, true), (1, true), (2, false), (4, false), (9, false)] {
        let (client, _fake) = start(FetchScript::HitWithFunction(function)).await;
        let found = client
            .fetch_blob_by_checksum(
                &RemoteExecutionMetadata::default(),
                URL,
                "sha512",
                SHA512_HEX,
            )
            .await
            .unwrap();
        assert_eq!(found, hit.then(digest), "digest function {function}");
    }
}

/// The lookup is one attempt: a server that is unavailable is asked once, not retried with
/// backoff while the build waits. The error carries the status code, which is how the caller
/// tells a server that is down from one that lacks the API.
#[tokio::test]
async fn fetch_unavailable_is_one_attempt() {
    let (client, fake) = start(FetchScript::Unavailable).await;

    let err = client
        .fetch_blob_by_checksum(
            &RemoteExecutionMetadata::default(),
            URL,
            "sha512",
            SHA512_HEX,
        )
        .await
        .unwrap_err();

    assert_eq!(fake.recorded.lock().unwrap().fetches.len(), 1);
    let re_error = err.downcast_ref::<crate::REClientError>().unwrap();
    assert_eq!(re_error.code, crate::TCode::UNAVAILABLE);
}

/// `UNIMPLEMENTED` reaches the caller as such, so it can stop asking a server that lacks the API.
#[tokio::test]
async fn fetch_unimplemented_is_reported_as_unimplemented() {
    let (client, fake) = start(FetchScript::Unimplemented).await;

    let err = client
        .fetch_blob_by_checksum(
            &RemoteExecutionMetadata::default(),
            URL,
            "sha512",
            SHA512_HEX,
        )
        .await
        .unwrap_err();

    assert_eq!(fake.recorded.lock().unwrap().fetches.len(), 1);
    let re_error = err.downcast_ref::<crate::REClientError>().unwrap();
    assert_eq!(re_error.code, crate::TCode::UNIMPLEMENTED);
}

/// The API takes the hash as hex and the wire carries it as a Subresource Integrity token:
/// `<algorithm>-<base64 of the raw bytes>`. Catches a token that base64-encodes the hex text
/// instead of the bytes, or one built without the algorithm prefix.
#[test]
fn qualifier_is_the_standard_sri_form_of_the_hex() {
    let sha512 = crate::client::checksum_qualifier(
        "sha512",
        "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425",
    )
    .unwrap();
    assert_eq!(sha512.name, "checksum.sri");
    assert_eq!(
        sha512.value,
        "sha512-ClAmHr0aOQ/tK/Mm8mc8FFWCpjQtUjIElz0CGTN/gWFqgGmwElh89WNfaSXxtWw2AjDBmyc1AO4BPgMGAb8kJQ=="
    );

    let sha256 = crate::client::checksum_qualifier(
        "sha256",
        "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
    )
    .unwrap();
    assert_eq!(
        sha256.value,
        "sha256-w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI="
    );
}

/// Text that is not hex is refused before anything is sent, rather than sent as a token that
/// names some other content.
#[tokio::test]
async fn non_hex_is_refused_without_a_request() {
    let (client, fake) = start(FetchScript::Hit).await;

    assert!(
        client
            .fetch_blob_by_checksum(&RemoteExecutionMetadata::default(), URL, "sha512", "xyz")
            .await
            .is_err()
    );
    assert!(
        client
            .push_blob_by_checksum(
                &RemoteExecutionMetadata::default(),
                URL,
                "sha512",
                "xyz",
                &digest()
            )
            .await
            .is_err()
    );

    let recorded = fake.recorded.lock().unwrap();
    assert!(recorded.fetches.is_empty());
    assert!(recorded.pushes.is_empty());
}
