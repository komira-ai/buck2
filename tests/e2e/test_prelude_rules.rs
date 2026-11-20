/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Context;
use buck2_e2e::http::StaticHttpServer;
use buck2_e2e::prelude::*;
use buck2_e2e::utils::random_string;
use serde_json::Value;
use sha2::Digest;

async fn output(buck: &Buck, target: &str) -> anyhow::Result<PathBuf> {
    let res = buck
        .build_without_report(&[target, "--show-full-simple-output"])
        .await?;
    Ok(PathBuf::from(res.stdout.trim()))
}

/// The `value` attribute of every target in the package, by target name.
async fn values(buck: &Buck, package: &str) -> anyhow::Result<BTreeMap<String, Value>> {
    let res = buck
        .uquery(&["--output-attribute", "value", &format!("root//{package}:")])
        .await?;
    let targets: serde_json::Map<String, Value> = serde_json::from_str(&res.stdout)?;
    targets
        .iter()
        .map(|(target, attrs)| {
            let name = target
                .split(':')
                .nth(1)
                .with_context(|| format!("`{target}` has no name"))?;
            let value = attrs
                .get("value")
                .with_context(|| format!("`{target}` has no `value`"))?;
            Ok((name.to_owned(), value.clone()))
        })
        .collect()
}

fn expected(values: &[(&str, &str)]) -> BTreeMap<String, Value> {
    values
        .iter()
        .map(|(name, value)| ((*name).to_owned(), Value::from(*value)))
        .collect()
}

// prelude/apple/apple_bundle_destination.bzl `bundle_relative_path_for_destination`
#[buck_test(inplace = false)]
async fn test_extensionkit_extensions_destination(buck: &Buck) -> anyhow::Result<()> {
    assert_eq!(
        values(buck, "bundle").await?,
        expected(&[
            ("iphoneos_app_extensionkit", "Extensions"),
            ("macosx_app_extensionkit", "Contents/Extensions"),
            ("maccatalyst_app_extensionkit", "Contents/Extensions"),
        ])
    );
    Ok(())
}

// prelude/cxx/headers.bzl `_infer_include_prefix_from_paths`
#[buck_test(inplace = false)]
async fn test_include_prefix_needs_a_whole_path_suffix(buck: &Buck) -> anyhow::Result<()> {
    assert_eq!(
        values(buck, "headers").await?,
        expected(&[
            ("renamed_header_prefix", "None"),
            ("subdir_header_prefix", "third-party/foo/config"),
        ])
    );
    Ok(())
}

// prelude/cxx/cxx_sources.bzl `get_srcs_with_flags`
#[buck_test(inplace = false)]
async fn test_distinct_flag_sets_compile_separately(buck: &Buck) -> anyhow::Result<()> {
    for target in ["colliding_flag_sets", "quote_colliding_flag_sets"] {
        let out = output(buck, &format!("root//srcs_flags:{target}")).await?;
        assert_eq!(
            std::fs::read_to_string(out)?
                .split_whitespace()
                .collect::<Vec<_>>(),
            ["0", "1"],
            "{target}"
        );
    }
    let out = output(buck, "root//srcs_flags:repeated_flag_set").await?;
    assert_eq!(
        std::fs::read_to_string(out)?
            .split_whitespace()
            .collect::<Vec<_>>(),
        ["None"]
    );
    Ok(())
}

/// The targets that a uquery prints, sorted.
async fn query(buck: &Buck, query: &str) -> anyhow::Result<Vec<String>> {
    let res = buck.uquery(&[query]).await?;
    let mut targets: Vec<String> = res.stdout.lines().map(str::to_owned).collect();
    targets.sort();
    Ok(targets)
}

// prelude/lean/library.bzl `covers`
#[buck_test(inplace = false)]
async fn test_queries_find_the_lean_target_that_covers_a_file(buck: &Buck) -> anyhow::Result<()> {
    let spec = ["root//lean_covers:spec"];
    let covered = "lean_covers/code/add.txt";
    assert_eq!(
        query(buck, &format!("kind('^lean_', owner({covered}))")).await?,
        spec
    );
    assert_eq!(
        query(
            buck,
            &format!(r"attrregexfilter(covers, 'code/add\.txt$', owner({covered}))")
        )
        .await?,
        spec
    );

    // A file that the library reads, but does not cover: the library owns it too, and only the
    // query on `covers` tells the two apart.
    let resource = "lean_covers/Spec/notes.txt";
    assert_eq!(
        query(buck, &format!("kind('^lean_', owner({resource}))")).await?,
        spec
    );
    assert_eq!(
        query(
            buck,
            &format!(r"attrregexfilter(covers, 'Spec/notes\.txt$', owner({resource}))")
        )
        .await?,
        Vec::<String>::new()
    );

    assert_eq!(
        query(buck, "owner(lean_covers/code/sub.txt)").await?,
        Vec::<String>::new()
    );
    Ok(())
}

#[buck_test(inplace = false)]
async fn test_covers_attribute_has_the_files_of_a_lean_target(buck: &Buck) -> anyhow::Result<()> {
    let res = buck
        .uquery(&["--output-attribute", "^covers$", "root//lean_covers:"])
        .await?;
    let targets: Value = serde_json::from_str(&res.stdout)?;
    assert_eq!(
        targets,
        serde_json::json!({
            "root//lean_covers:spec": {
                "covers": ["root//lean_covers/code/add.txt", "root//lean_covers/code/mul.txt"],
            },
            "root//lean_covers:spec_check": {"covers": null},
        })
    );
    Ok(())
}

// prelude/lean/library.bzl `lean_default_info`
#[buck_test(inplace = false)]
async fn test_covers_sub_target_is_a_directory_of_the_files(buck: &Buck) -> anyhow::Result<()> {
    let res = buck
        .build(&["root//lean_covers_dir:covered[covers]"])
        .await?;
    let dir = res
        .build_report()?
        .output_for_sub_target("root//lean_covers_dir:covered", "covers")?;
    assert_eq!(std::fs::read_to_string(dir.join("a.txt"))?, "a\n");
    assert_eq!(
        std::fs::read_to_string(dir.join("sub").join("b.txt"))?,
        "b\n"
    );
    Ok(())
}

#[buck_test(inplace = false)]
async fn test_covers_without_a_file_is_an_error(buck: &Buck) {
    buck.build(&["root//lean_covers_dir:no_file"])
        .await
        .expect_failure()
        .assert_stderr_matches("`covers` names no file");
}

#[buck_test(inplace = false)]
async fn test_a_target_in_covers_is_an_error(buck: &Buck) {
    // The second target names a file of another package through an `export_file`: its output is
    // a source file, at the path of a file that the target covers in its own package.
    for (target, label) in [
        ("output_of_a_target", "root//lean_covers_dir:generated"),
        ("source_of_a_target", "root//lean_covers_other:a_txt"),
    ] {
        buck.build(&[&format!("root//lean_covers_dir:{target}")])
            .await
            .expect_failure()
            .assert_stderr_matches(&format!(
                "`covers` takes files of the package, and `{label}` is a target"
            ));
    }
}

#[buck_test(inplace = false)]
async fn test_build_fails_on_a_covered_file_that_does_not_exist(buck: &Buck) {
    // No action of the default output reads the file. Open source buck2 fails earlier, when it
    // reads the build file.
    buck.build(&["root//lean_covers_missing:missing_file"])
        .await
        .expect_failure()
        .assert_stderr_matches(r"missing\.txt`.*does not exist");
}

// prelude/sh_binary.bzl `_generate_script`
#[buck_test(inplace = false, skip_for_os = ["windows"])]
async fn test_two_resources_at_one_link_are_an_error(buck: &Buck) {
    buck.run(&["root//sh_resources:show"])
        .await
        .expect_failure()
        .assert_stderr_matches("would both be placed at `sh_resources/gen`");
}

#[buck_test(inplace = false, skip_for_os = ["windows"])]
async fn test_a_resource_at_the_main_link_is_an_error(buck: &Buck) {
    buck.build(&["root//sh_resources:resource_at_main_link"])
        .await
        .expect_failure()
        .assert_stderr_matches("would both be placed at `show.sh`");
}

// prelude/http_archive/unarchive.bzl `unarchive`
#[buck_test(inplace = false, skip_for_os = ["windows", "darwin"])]
async fn test_excluded_names_are_read_by_tar_as_globs(buck: &Buck) -> anyhow::Result<()> {
    // The exclusion list holds the member names that matched the `excludes`
    // regexes, but tar reads every `--exclude-from` line as a glob: `[id].js`
    // keeps the excluded file and drops `i.js` and `d.js` instead.
    let out = output(buck, "root//archive:unpacked").await?;
    let mut names = std::fs::read_dir(out.join("pages"))?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    names.sort();
    assert_eq!(names, ["[id].js", "keep.js"]);
    Ok(())
}

// prelude/http_file.bzl `http_file_shared`, through `http_file` and `remote_file`
#[buck_test(inplace = false, skip_for_os = ["windows"])]
async fn test_a_sha512_alone_is_a_checksum(buck: &Buck) -> anyhow::Result<()> {
    let content = random_string().into_bytes();
    let sha512 = hex::encode(sha2::Sha512::digest(&content));
    let server = StaticHttpServer::start([("/file", content.clone())]).await?;
    let url_config = format!("test.url={}", server.url("/file"));
    let sha512_config = format!("test.sha512={sha512}");
    for target in ["root//download:http_file", "root//download:remote_file"] {
        let mut args = vec![target, "--show-full-simple-output"];
        args.extend(["-c", &url_config, "-c", &sha512_config]);
        let res = buck.build_without_report(&args).await?;
        assert_eq!(std::fs::read(res.stdout.trim())?, content, "{target}");
    }
    Ok(())
}

/// A ustar archive holding one regular file, `name`, with `content`.
fn tar_of(name: &str, content: &[u8]) -> Vec<u8> {
    fn field(header: &mut [u8], at: usize, value: &[u8]) {
        header[at..at + value.len()].copy_from_slice(value);
    }
    let mut header = [0u8; 512];
    field(&mut header, 0, name.as_bytes());
    field(&mut header, 100, b"0000644\0");
    field(&mut header, 108, b"0000000\0");
    field(&mut header, 116, b"0000000\0");
    field(
        &mut header,
        124,
        format!("{:011o}\0", content.len()).as_bytes(),
    );
    field(&mut header, 136, b"00000000000\0");
    field(&mut header, 156, b"0");
    field(&mut header, 257, b"ustar\0");
    field(&mut header, 263, b"00");
    // The checksum is the sum of the header's bytes with its own field read as spaces.
    field(&mut header, 148, b"        ");
    let checksum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    field(&mut header, 148, format!("{checksum:06o}\0 ").as_bytes());

    let mut archive = header.to_vec();
    archive.extend_from_slice(content);
    archive.resize(archive.len().next_multiple_of(512), 0);
    // Two zero blocks end the archive.
    archive.resize(archive.len() + 1024, 0);
    archive
}

// prelude/http_archive/http_archive.bzl `http_archive_impl`
#[buck_test(inplace = false, skip_for_os = ["windows"])]
async fn test_an_http_archive_with_a_sha512_alone_is_unpacked(buck: &Buck) -> anyhow::Result<()> {
    let content = random_string().into_bytes();
    let archive = tar_of("file.txt", &content);
    let sha512 = hex::encode(sha2::Sha512::digest(&archive));
    let server = StaticHttpServer::start([("/archive", archive)]).await?;
    let res = buck
        .build_without_report(&[
            "root//download:http_archive",
            "--show-full-simple-output",
            "-c",
            &format!("test.url={}", server.url("/archive")),
            "-c",
            &format!("test.sha512={sha512}"),
        ])
        .await?;
    let unpacked = PathBuf::from(res.stdout.trim());
    assert_eq!(std::fs::read(unpacked.join("file.txt"))?, content);
    Ok(())
}

// prelude/http_file.bzl `http_file_shared`, through `http_file` and `remote_file`, and
// prelude/http_archive/http_archive.bzl `http_archive_impl`
#[buck_test(inplace = false, skip_for_os = ["windows"])]
async fn test_a_wrong_sha512_fails_the_download(buck: &Buck) -> anyhow::Result<()> {
    let content = random_string().into_bytes();
    let wrong = "0".repeat(128);
    let server = StaticHttpServer::start([("/file", content.clone())]).await?;
    let url = server.url("/file");
    for target in [
        "root//download:http_file",
        "root//download:remote_file",
        "root//download:http_archive",
    ] {
        buck.build(&[
            target,
            "-c",
            &format!("test.url={url}"),
            "-c",
            &format!("test.sha512={wrong}"),
        ])
        .await
        .expect_failure()
        .assert_stderr_matches(&format!(
            "Invalid sha512 digest. Expected {wrong}, got {}",
            hex::encode(sha2::Sha512::digest(&content))
        ));
    }
    Ok(())
}
