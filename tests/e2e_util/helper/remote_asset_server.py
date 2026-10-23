# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is dual-licensed under either the MIT license found in the
# LICENSE-MIT file in the root directory of this source tree or the Apache
# License, Version 2.0 found in the LICENSE-APACHE file in the root directory
# of this source tree. You may select, at your option, one of the
# above-listed licenses.

# pyre-strict

"""
An in-memory Remote Execution CAS with a Remote Asset server on the same port, for end-to-end
tests of what buck2 does with them. It implements what a build that has no remote actions needs:
Capabilities, ContentAddressableStorage, ByteStream, an ActionCache that never hits, and the
Remote Asset Fetch and Push services. The message and service classes are generated from the
`.proto` files buck2 itself is built with (`remote_execution/oss/re_grpc_proto/proto`), so the
fake and the client cannot drift apart on the wire format.

Needs `grpcio` and `grpcio-tools`.
"""

import base64
import hashlib
import importlib
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import grpc
import grpc_tools
from grpc_tools import protoc

_PROTO_ROOT = (
    Path(__file__).resolve().parents[3]
    / "remote_execution"
    / "oss"
    / "re_grpc_proto"
    / "proto"
)


_BLOB_RESOURCE = re.compile(r"blobs/([0-9a-f]+)/(\d+)$")

_generated: Optional[Dict[str, Any]] = None


def _generate() -> Dict[str, Any]:
    """Compiles the protos once per process and returns the generated modules by short name."""
    global _generated
    if _generated is not None:
        return _generated
    out = tempfile.mkdtemp(prefix="remote_asset_protos")
    well_known = Path(grpc_tools.__file__).parent / "_proto"
    argv = [
        "protoc",
        f"-I{_PROTO_ROOT}",
        f"-I{well_known}",
        f"--python_out={out}",
        f"--grpc_python_out={out}",
    ]
    code = protoc.main(argv + sorted(str(p) for p in _PROTO_ROOT.rglob("*.proto")))
    assert code == 0, "protoc failed on buck2's Remote Execution protos"
    sys.path.insert(0, out)
    names = {
        "re": "build.bazel.remote.execution.v2.remote_execution_pb2",
        "re_grpc": "build.bazel.remote.execution.v2.remote_execution_pb2_grpc",
        "asset": "build.bazel.remote.asset.v1.remote_asset_pb2",
        "asset_grpc": "build.bazel.remote.asset.v1.remote_asset_pb2_grpc",
        "bs": "google.bytestream.bytestream_pb2",
        "bs_grpc": "google.bytestream.bytestream_pb2_grpc",
        "status": "google.rpc.status_pb2",
        "semver": "build.bazel.semver.semver_pb2",
    }
    _generated = {short: importlib.import_module(full) for short, full in names.items()}
    return _generated


def sri(algorithm: str, content: bytes) -> str:
    """The Subresource Integrity token (`sha512-<base64>`) of `content`."""
    raw = hashlib.new(algorithm, content).digest()
    return f"{algorithm}-{base64.b64encode(raw).decode()}"


class RemoteAssetServer:
    """
    Listens on a loopback port and records what it is asked.

    `fetches` holds one `(uri, sri_token)` per `FetchBlob`, and `pushes` one `(uri, sri_token,
    blob_hash, blob_size)` per accepted `PushBlob`. A push is refused (and counted in `refused`)
    when the blob is not in the CAS or when the content does not match the token, as a real
    server should. `uploads` holds the hashes of the blobs written to the CAS, in order.

    With `implement_assets=False` the Remote Asset services answer `UNIMPLEMENTED`, as a plain
    CAS does.
    """

    def __init__(self, *, implement_assets: bool = True) -> None:
        self._implement_assets = implement_assets
        self.blobs: Dict[str, bytes] = {}
        self.assets: Dict[Tuple[str, str], Tuple[str, int]] = {}
        self.fetches: List[Tuple[str, str]] = []
        self.pushes: List[Tuple[str, str, str, int]] = []
        self.refused: List[Tuple[str, str]] = []
        self.uploads: List[str] = []
        self.reads: List[str] = []
        self._server: Any = None
        self._port: Optional[int] = None

    @property
    def address(self) -> str:
        return f"grpc://127.0.0.1:{self._port}"

    def buckconfig(self) -> str:
        """The `.buckconfig` section that points buck2's RE client here."""
        return (
            "[buck2_re_client]\n"
            f"engine_address = {self.address}\n"
            f"cas_address = {self.address}\n"
            f"action_cache_address = {self.address}\n"
            "tls = false\n"
        )

    async def __aenter__(self) -> "RemoteAssetServer":
        pb = _generate()
        server = grpc.aio.server()
        outer = self

        def digest(hash_: str, size: int) -> Any:
            return pb["re"].Digest(hash=hash_, size_bytes=size)

        class Capabilities(pb["re_grpc"].CapabilitiesServicer):  # type: ignore
            async def GetCapabilities(self, request: Any, context: Any) -> Any:
                re = pb["re"]
                return re.ServerCapabilities(
                    cache_capabilities=re.CacheCapabilities(
                        digest_functions=[re.DigestFunction.SHA256],
                        max_batch_total_size_bytes=4 * 1024 * 1024,
                        action_cache_update_capabilities=re.ActionCacheUpdateCapabilities(
                            update_enabled=False
                        ),
                    ),
                    low_api_version=pb["semver"].SemVer(major=2),
                    high_api_version=pb["semver"].SemVer(major=2, minor=3),
                )

        class Cas(pb["re_grpc"].ContentAddressableStorageServicer):  # type: ignore
            async def FindMissingBlobs(self, request: Any, context: Any) -> Any:
                missing = [d for d in request.blob_digests if d.hash not in outer.blobs]
                return pb["re"].FindMissingBlobsResponse(missing_blob_digests=missing)

            async def BatchUpdateBlobs(self, request: Any, context: Any) -> Any:
                responses = []
                for r in request.requests:
                    ok = hashlib.sha256(r.data).hexdigest() == r.digest.hash
                    if ok:
                        outer.blobs[r.digest.hash] = bytes(r.data)
                        outer.uploads.append(r.digest.hash)
                    responses.append(
                        pb["re"].BatchUpdateBlobsResponse.Response(
                            digest=r.digest,
                            status=pb["status"].Status(code=0 if ok else 3),
                        )
                    )
                return pb["re"].BatchUpdateBlobsResponse(responses=responses)

            async def BatchReadBlobs(self, request: Any, context: Any) -> Any:
                responses = []
                for d in request.digests:
                    data = outer.blobs.get(d.hash)
                    if data is not None:
                        outer.reads.append(d.hash)
                    responses.append(
                        pb["re"].BatchReadBlobsResponse.Response(
                            digest=d,
                            data=data or b"",
                            status=pb["status"].Status(code=0 if data is not None else 5),
                        )
                    )
                return pb["re"].BatchReadBlobsResponse(responses=responses)

        class ActionCache(pb["re_grpc"].ActionCacheServicer):  # type: ignore
            async def GetActionResult(self, request: Any, context: Any) -> Any:
                await context.abort(grpc.StatusCode.NOT_FOUND, "no cached actions")

        class ByteStream(pb["bs_grpc"].ByteStreamServicer):  # type: ignore
            async def Read(self, request: Any, context: Any) -> Any:
                m = _BLOB_RESOURCE.search(request.resource_name)
                data = outer.blobs.get(m.group(1)) if m else None
                if data is None:
                    await context.abort(grpc.StatusCode.NOT_FOUND, "no such blob")
                outer.reads.append(m.group(1))
                data = data[request.read_offset :]
                for start in range(0, max(len(data), 1), 1 << 20):
                    yield pb["bs"].ReadResponse(data=data[start : start + (1 << 20)])

            async def Write(self, request_iterator: Any, context: Any) -> Any:
                name = None
                data = b""
                async for r in request_iterator:
                    name = name or r.resource_name
                    data += r.data
                m = _BLOB_RESOURCE.search(name or "")
                if m is None or hashlib.sha256(data).hexdigest() != m.group(1):
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "bad upload")
                outer.blobs[m.group(1)] = data
                outer.uploads.append(m.group(1))
                return pb["bs"].WriteResponse(committed_size=len(data))

        class Fetch(pb["asset_grpc"].FetchServicer):  # type: ignore
            async def FetchBlob(self, request: Any, context: Any) -> Any:
                if not outer._implement_assets:
                    await context.abort(grpc.StatusCode.UNIMPLEMENTED, "Fetch")
                tokens = [q.value for q in request.qualifiers if q.name == "checksum.sri"]
                for uri in request.uris:
                    for token in tokens:
                        outer.fetches.append((uri, token))
                        found = outer.assets.get((uri, token))
                        if found is not None:
                            return pb["asset"].FetchBlobResponse(
                                blob_digest=digest(*found),
                                digest_function=pb["re"].DigestFunction.SHA256,
                            )
                await context.abort(grpc.StatusCode.NOT_FOUND, "no such asset")

        class Push(pb["asset_grpc"].PushServicer):  # type: ignore
            async def PushBlob(self, request: Any, context: Any) -> Any:
                if not outer._implement_assets:
                    await context.abort(grpc.StatusCode.UNIMPLEMENTED, "Push")
                token = next(
                    (q.value for q in request.qualifiers if q.name == "checksum.sri"), ""
                )
                blob = request.blob_digest
                data = outer.blobs.get(blob.hash)
                algorithm = token.split("-", 1)[0]
                for uri in request.uris:
                    # Only record an alias for content the CAS holds and that has the hash the
                    # token names: the server, not the client, vouches for the alias.
                    if (
                        data is None
                        or algorithm not in hashlib.algorithms_available
                        or sri(algorithm, data) != token
                    ):
                        outer.refused.append((uri, token))
                        await context.abort(
                            grpc.StatusCode.FAILED_PRECONDITION, "blob does not match"
                        )
                    outer.assets[(uri, token)] = (blob.hash, blob.size_bytes)
                    outer.pushes.append((uri, token, blob.hash, blob.size_bytes))
                return pb["asset"].PushBlobResponse()

        pb["re_grpc"].add_CapabilitiesServicer_to_server(Capabilities(), server)
        pb["re_grpc"].add_ContentAddressableStorageServicer_to_server(Cas(), server)
        pb["re_grpc"].add_ActionCacheServicer_to_server(ActionCache(), server)
        pb["bs_grpc"].add_ByteStreamServicer_to_server(ByteStream(), server)
        pb["asset_grpc"].add_FetchServicer_to_server(Fetch(), server)
        pb["asset_grpc"].add_PushServicer_to_server(Push(), server)
        self._port = server.add_insecure_port("127.0.0.1:0")
        await server.start()
        self._server = server
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._server.stop(None)
