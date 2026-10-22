# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is dual-licensed under either the MIT license found in the
# LICENSE-MIT file in the root directory of this source tree or the Apache
# License, Version 2.0 found in the LICENSE-APACHE file in the root directory
# of this source tree. You may select, at your option, one of the
# above-listed licenses.

# pyre-strict

"""
`download_file` with remote execution configured: a download that its checksums do not give a CAS
digest for is looked up in, and recorded with, a Remote Asset server. The server here is a fake
CAS plus Remote Asset server on a loopback port (see `remote_asset_server.py`), and the file's
origin is a local HTTP server, so a test can count exactly what each of them was asked.
"""

import hashlib
import re
import shutil
from typing import Dict, List, Optional

from buck2.tests.e2e_util.api.buck import Buck
from buck2.tests.e2e_util.asserts import expect_failure
from buck2.tests.e2e_util.buck_workspace import buck_test
from buck2.tests.e2e_util.helper.http_server import StaticHttpServer
from buck2.tests.e2e_util.helper.remote_asset_server import RemoteAssetServer, sri
from buck2.tests.e2e_util.helper.utils import random_string


def digest(algorithm: str, content: bytes) -> str:
    return hashlib.new(algorithm, content).hexdigest()


def configs(
    url: str, declared: Dict[str, str], *, size: Optional[int] = None
) -> List[str]:
    args = ["-c", f"test.url={url}"]
    for algorithm, hex_digest in declared.items():
        args += ["-c", f"test.{algorithm}={hex_digest}"]
    if size is not None:
        args += ["-c", f"test.size_bytes={size}"]
    return args


def use_remote_asset(buck: Buck, server: RemoteAssetServer) -> None:
    """Points the project at the fake, with a CAS keyed by SHA256, as Remote Asset requires."""
    with open(buck.cwd / ".buckconfig", "a") as buckconfig:
        buckconfig.write("[buck2]\ndigest_algorithms = SHA256\n")
        buckconfig.write(server.buckconfig())


async def build_from_scratch(buck: Buck, *args: str) -> bytes:
    """A build in a new daemon with an empty `buck-out`, which is what another machine has."""
    await buck.kill()
    shutil.rmtree(buck.cwd / "buck-out", ignore_errors=True)
    result = await buck.build("//:download", *args)
    return result.get_build_report().output_for_target("//:download").read_bytes()


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_a_second_clean_build_downloads_nothing(buck: Buck) -> None:
    content = random_string().encode()
    sha512 = digest("sha512", content)
    async with RemoteAssetServer() as ra, StaticHttpServer({"/file": content}) as origin:
        use_remote_asset(buck, ra)
        url = origin.url("/file")
        declared = configs(url, {"sha512": sha512})

        # The first build asks, misses, downloads, uploads the blob and records it.
        first = await buck.build("//:download", *declared)
        assert (
            first.get_build_report().output_for_target("//:download").read_bytes()
            == content
        )
        assert origin.count("GET", "/file") == 1
        assert ra.fetches == [(url, sri("sha512", content))]
        assert ra.uploads == [digest("sha256", content)]
        assert ra.pushes == [
            (url, sri("sha512", content), digest("sha256", content), len(content))
        ]
        assert ra.refused == []

        # A new daemon, an empty `buck-out`: the file is nowhere on disk. The server knows it,
        # so it comes out of the CAS and the origin sees nothing at all.
        before = len(origin.requests)
        assert await build_from_scratch(buck, *declared) == content
        assert len(origin.requests) == before
        assert len(ra.fetches) == 2
        assert ra.fetches[1] == (url, sri("sha512", content))
        assert len(ra.pushes) == 1
        assert digest("sha256", content) in ra.reads


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_the_record_is_per_url_and_per_hash(buck: Buck) -> None:
    content = random_string().encode()
    other = random_string().encode()
    async with RemoteAssetServer() as ra, StaticHttpServer(
        {"/file": content, "/other": other, "/mirror": content}
    ) as origin:
        use_remote_asset(buck, ra)
        await buck.build(
            "//:download", *configs(origin.url("/file"), {"sha512": digest("sha512", content)})
        )
        assert origin.count("GET", "/file") == 1

        # The same hash at another URL is a different asset to the server, so it is a miss
        # and the bytes come from that URL.
        assert (
            await build_from_scratch(
                buck, *configs(origin.url("/mirror"), {"sha512": digest("sha512", content)})
            )
            == content
        )
        assert origin.count("GET", "/mirror") == 1

        # Another hash at the first URL is a miss as well (and the download then refuses the
        # bytes, since they do not have that hash).
        await buck.kill()
        shutil.rmtree(buck.cwd / "buck-out", ignore_errors=True)
        await expect_failure(
            buck.build(
                "//:download",
                *configs(origin.url("/file"), {"sha512": digest("sha512", other)}),
            ),
            stderr_regex="Invalid sha512 digest",
        )
        assert origin.count("GET", "/file") == 2


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_a_sha512_with_other_checksums_is_recorded_under_the_sha512(
    buck: Buck,
) -> None:
    content = random_string().encode()
    async with RemoteAssetServer() as ra, StaticHttpServer({"/file": content}) as origin:
        use_remote_asset(buck, ra)
        url = origin.url("/file")
        declared = configs(
            url,
            {"sha1": digest("sha1", content), "sha512": digest("sha512", content)},
        )
        await buck.build("//:download", *declared)
        assert [p[:2] for p in ra.pushes] == [(url, sri("sha512", content))]

        before = len(origin.requests)
        assert await build_from_scratch(buck, *declared) == content
        assert len(origin.requests) == before


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_a_download_that_fails_its_checksum_is_not_recorded(buck: Buck) -> None:
    content = random_string().encode()
    async with RemoteAssetServer() as ra, StaticHttpServer({"/file": content}) as origin:
        use_remote_asset(buck, ra)
        wrong = "0" * 128
        await expect_failure(
            buck.build("//:download", *configs(origin.url("/file"), {"sha512": wrong})),
            stderr_regex=re.escape(f"Invalid sha512 digest. Expected {wrong}"),
        )
        assert origin.count("GET", "/file") == 1
        assert ra.pushes == []
        assert ra.uploads == []
        assert ra.assets == {}


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_a_server_without_remote_asset_changes_nothing_for_the_build(
    buck: Buck,
) -> None:
    content = random_string().encode()
    async with RemoteAssetServer(implement_assets=False) as ra, StaticHttpServer(
        {"/file": content}
    ) as origin:
        use_remote_asset(buck, ra)
        url = origin.url("/file")
        declared = configs(url, {"sha512": digest("sha512", content)})

        first = await buck.build("//:download", *declared)
        assert (
            first.get_build_report().output_for_target("//:download").read_bytes()
            == content
        )
        assert origin.count("GET", "/file") == 1
        assert ra.pushes == []

        # Nothing was recorded, so the next clean build downloads again, and succeeds.
        assert await build_from_scratch(buck, *declared) == content
        assert origin.count("GET", "/file") == 2


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_downloads_that_give_a_cas_digest_do_not_use_remote_asset(
    buck: Buck,
) -> None:
    content = random_string().encode()
    async with RemoteAssetServer() as ra, StaticHttpServer({"/file": content}) as origin:
        use_remote_asset(buck, ra)
        url = origin.url("/file")
        for declared in (
            {"sha256": digest("sha256", content)},
            {"sha1": digest("sha1", content)},
            {"sha1": digest("sha1", content), "sha256": digest("sha256", content)},
        ):
            await buck.kill()
            shutil.rmtree(buck.cwd / "buck-out", ignore_errors=True)
            result = await buck.build(
                "//:download", *configs(url, declared, size=len(content))
            )
            assert (
                result.get_build_report().output_for_target("//:download").read_bytes()
                == content
            )
        assert ra.fetches == []
        assert ra.pushes == []
