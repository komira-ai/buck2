# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is dual-licensed under either the MIT license found in the
# LICENSE-MIT file in the root directory of this source tree or the Apache
# License, Version 2.0 found in the LICENSE-APACHE file in the root directory
# of this source tree. You may select, at your option, one of the
# above-listed licenses.

# pyre-strict

import hashlib
import re
from typing import Dict, List, Optional

import pytest
from buck2.tests.e2e_util.api.buck import Buck
from buck2.tests.e2e_util.api.buck_result import BuildResult
from buck2.tests.e2e_util.asserts import expect_failure
from buck2.tests.e2e_util.buck_workspace import buck_test
from buck2.tests.e2e_util.helper.http_server import StaticHttpServer
from buck2.tests.e2e_util.helper.utils import random_string

ALGORITHMS = ["sha1", "sha256", "sha512"]


def digest(algorithm: str, content: bytes) -> str:
    return hashlib.new(algorithm, content).hexdigest()


def wrong_digest(algorithm: str) -> str:
    """A well-formed digest of `algorithm` that no content has."""
    return "0" * len(digest(algorithm, b""))


def configs(
    url: str, declared: Dict[str, str], *, size: Optional[int] = None
) -> List[str]:
    """`-c` arguments declaring the download the fixture's target reads from the config."""
    args = ["-c", f"test.url={url}"]
    for algorithm, hex_digest in declared.items():
        args += ["-c", f"test.{algorithm}={hex_digest}"]
    if size is not None:
        args += ["-c", f"test.size_bytes={size}"]
    return args


def declare(content: bytes, *algorithms: str) -> Dict[str, str]:
    return {algorithm: digest(algorithm, content) for algorithm in algorithms}


def output_of(result: BuildResult) -> bytes:
    return result.get_build_report().output_for_target("//:download").read_bytes()


# Which checksums the rule passes to `download_file`. Every combination of the three
# algorithms is a declaration that has to download and verify.
SHAPES = [
    ("sha1",),
    ("sha256",),
    ("sha512",),
    ("sha1", "sha256"),
    ("sha1", "sha512"),
    ("sha256", "sha512"),
    ("sha1", "sha256", "sha512"),
]


@buck_test(data_dir="download", skip_for_os=["windows"])
@pytest.mark.parametrize("shape", SHAPES, ids=["+".join(s) for s in SHAPES])
async def test_downloads_with_every_combination_of_checksums(
    buck: Buck, shape: tuple[str, ...]
) -> None:
    content = random_string().encode()
    async with StaticHttpServer({"/file": content}) as server:
        result = await buck.build(
            "//:download", *configs(server.url("/file"), declare(content, *shape))
        )
        assert output_of(result) == content
        assert server.count("GET", "/file") == 1


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_a_sha512_in_capitals_is_accepted(buck: Buck) -> None:
    content = random_string().encode()
    async with StaticHttpServer({"/file": content}) as server:
        declared = {"sha512": digest("sha512", content).upper()}
        result = await buck.build(
            "//:download", *configs(server.url("/file"), declared)
        )
        assert output_of(result) == content


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_a_sha512_with_the_right_size_downloads(buck: Buck) -> None:
    content = random_string().encode()
    async with StaticHttpServer({"/file": content}) as server:
        result = await buck.build(
            "//:download",
            *configs(
                server.url("/file"),
                declare(content, "sha512"),
                size=len(content),
            ),
        )
        assert output_of(result) == content
        assert server.count("GET", "/file") == 1


# Each case names the algorithm whose digest is wrong and the algorithms declared next to it,
# which are right.
WRONG_DIGEST_CASES = [
    (wrong, others)
    for wrong in ALGORITHMS
    for others in ([], [a for a in ALGORITHMS if a != wrong])
]


@buck_test(data_dir="download", skip_for_os=["windows"])
@pytest.mark.parametrize(
    "wrong,others",
    WRONG_DIGEST_CASES,
    ids=[f"{w}_wrong_with_{'+'.join(o) or 'nothing'}" for w, o in WRONG_DIGEST_CASES],
)
async def test_a_wrong_digest_of_each_kind_fails_the_build(
    buck: Buck, wrong: str, others: List[str]
) -> None:
    content = random_string().encode()
    declared = declare(content, *others)
    declared[wrong] = wrong_digest(wrong)
    async with StaticHttpServer({"/file": content}) as server:
        url = server.url("/file")
        await expect_failure(
            buck.build("//:download", *configs(url, declared)),
            stderr_regex=re.escape(
                f"Invalid {wrong} digest. Expected {wrong_digest(wrong)}, "
                f"got {digest(wrong, content)}. URL: {url}"
            ),
        )
        # The content was fetched and then refused: the check is on the bytes.
        assert server.count("GET", "/file") == 1


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_a_sha512_that_is_not_a_digest_is_refused_before_any_download(
    buck: Buck,
) -> None:
    content = random_string().encode()
    async with StaticHttpServer({"/file": content}) as server:
        url = server.url("/file")
        too_short = digest("sha256", content)
        await expect_failure(
            buck.build("//:download", *configs(url, {"sha512": too_short})),
            stderr_regex=re.escape(
                "Invalid digest for `sha512` argument, expected length of 128 "
                f"but got 64, digest `{too_short}`"
            ),
        )
        not_hex = "z" * 128
        await expect_failure(
            buck.build("//:download", *configs(url, {"sha512": not_hex})),
            stderr_regex=re.escape(
                "Invalid digest for `sha512` argument, expected 0-9 a-z hex "
                "characters, but got `z`"
            ),
        )
        assert server.count("GET", "/file") == 0


@buck_test(data_dir="download", skip_for_os=["windows"])
async def test_a_sha512_alone_checks_the_declared_size(buck: Buck) -> None:
    content = random_string().encode()
    async with StaticHttpServer({"/file": content}) as server:
        await expect_failure(
            buck.build(
                "//:download",
                *configs(
                    server.url("/file"),
                    declare(content, "sha512"),
                    size=len(content) + 1,
                ),
            ),
            stderr_regex=f"Downloaded size \\({len(content)}\\) does not match expected size \\({len(content) + 1}\\)",
        )


# A checksum is part of an action, and an action is part of an analysis result, which can be
# paged out to disk and back while a daemon runs.
PAGING = {
    "buck2_hydration": {"enable_paging": "true", "page_out_min_free_disk_gb": "0"}
}


@buck_test(
    data_dir="download",
    skip_for_os=["windows"],
    write_invocation_record=True,
    extra_buck_config=PAGING,
)
@pytest.mark.parametrize("shape", SHAPES, ids=["+".join(s) for s in SHAPES])
async def test_a_paged_out_download_is_read_back(
    buck: Buck, shape: tuple[str, ...]
) -> None:
    content = random_string().encode()
    async with StaticHttpServer({"/file": content}) as server:
        args = configs(server.url("/file"), declare(content, *shape))
        assert output_of(await buck.build("//:download", *args)) == content

        await buck.debug("hydration", "page-out")
        status = (await buck.debug("hydration", "status")).stdout
        paged_out = re.search(r"(\d+) paged out", status)
        assert paged_out is not None and int(paged_out.group(1)) > 0, status

        result = await buck.build("//:download", *args)
        assert output_of(result) == content
        stats = result.invocation_record().get("page_in_by_key_type", {})
        assert int(stats.get("AnalysisKey", {}).get("count", 0)) > 0, stats
        assert server.count("GET", "/file") == 1
