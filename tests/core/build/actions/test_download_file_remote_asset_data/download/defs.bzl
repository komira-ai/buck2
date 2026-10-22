# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is dual-licensed under either the MIT license found in the
# LICENSE-MIT file in the root directory of this source tree or the Apache
# License, Version 2.0 found in the LICENSE-APACHE file in the root directory
# of this source tree. You may select, at your option, one of the
# above-listed licenses.

def _download_impl(ctx: AnalysisContext):
    output = ctx.actions.download_file(
        "download",
        ctx.attrs.url,
        sha1 = ctx.attrs.sha1,
        sha256 = ctx.attrs.sha256,
        sha512 = ctx.attrs.sha512,
        size_bytes = ctx.attrs.size_bytes,
        has_content_based_path = False,
    )
    return [DefaultInfo(default_output = output)]

download = rule(
    impl = _download_impl,
    attrs = {
        "sha1": attrs.option(attrs.string(), default = None),
        "sha256": attrs.option(attrs.string(), default = None),
        "sha512": attrs.option(attrs.string(), default = None),
        "size_bytes": attrs.option(attrs.int(), default = None),
        "url": attrs.string(),
    },
)

def _copy_impl(ctx: AnalysisContext):
    # Reads the download through a command, which needs the download's analysis result.
    out = ctx.actions.declare_output("out", has_content_based_path = False)
    ctx.actions.run(
        cmd_args(["cp", ctx.attrs.dep[DefaultInfo].default_outputs[0], out.as_output()]),
        category = "copy",
    )
    return [DefaultInfo(default_output = out)]

copy = rule(
    impl = _copy_impl,
    attrs = {
        "dep": attrs.dep(),
    },
)
