#!/usr/bin/env python3
"""Convert a single linux/arm64 docker-save archive to classic Docker format.

Build-time packaging only: no networking, extraction into a root filesystem,
container execution, or changes to image config/uncompressed layer contents.
Containerd's extra OCI index may advertise platforms not included in the save;
the single manifest.json entry and its actual config select the saved image.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tempfile
import zlib


CHUNK = 1 << 20
MAX_METADATA = 4 << 20
MAX_OUTER_MEMBERS = 10_000
MAX_LAYER_MEMBERS = 100_000
MAX_LAYER_BYTES = 512 << 20
MAX_TOTAL_BYTES = 1 << 30
DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")


class ConversionError(ValueError):
    pass


def safe_name(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ConversionError("invalid archive path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ConversionError("archive path traversal is forbidden")
    return str(path)


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def regular_member(members, name):
    name = safe_name(name)
    member = members.get(name)
    if member is None or not member.isfile():
        raise ConversionError("required archive member is missing or not a regular file")
    return member


def metadata(archive, members, name):
    member = regular_member(members, name)
    if member.size < 1 or member.size > MAX_METADATA:
        raise ConversionError("metadata exceeds size limit or is empty")
    with archive.extractfile(member) as stream:
        data = stream.read(MAX_METADATA + 1)
    if len(data) != member.size:
        raise ConversionError("truncated metadata")
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConversionError("invalid metadata JSON") from exc
    return data, parsed


def check_layer_paths(path):
    # Never extract layer members. Even links are inspected as metadata only.
    # Reject links escaping the layer's logical root rather than normalizing
    # them into a path that an eventual importer could interpret differently.
    count = 0
    with tarfile.open(path, "r|") as archive:
        for member in archive:
            count += 1
            if count > MAX_LAYER_MEMBERS:
                raise ConversionError("layer has too many archive members")
            name = safe_name(member.name)
            if member.issym() or member.islnk():
                target = member.linkname
                if not target or "\\" in target or "\x00" in target or PurePosixPath(target).is_absolute():
                    raise ConversionError("layer link escapes its logical root")
                # Symlinks are relative to their parent; tar hardlink names
                # are relative to the archive root.
                parts = list(PurePosixPath(name).parent.parts) if member.issym() else []
                for part in PurePosixPath(target).parts:
                    if part == "..":
                        if not parts:
                            raise ConversionError("layer link path traversal is forbidden")
                        parts.pop()
                    elif part != ".":
                        parts.append(part)


def spool_layer(archive, member, output, expected, remaining):
    limit = min(MAX_LAYER_BYTES, remaining)
    digest = hashlib.sha256()
    size = 0
    with archive.extractfile(member) as raw:
        magic = raw.read(2)
        raw.seek(0)
        stream = gzip.GzipFile(fileobj=raw, mode="rb") if magic == b"\x1f\x8b" else raw
        try:
            with open(output, "xb") as target:
                while True:
                    # Read at most one byte beyond the limit to reject a gzip
                    # expansion bomb without allocating the expanded layer.
                    block = stream.read(min(CHUNK, limit - size + 1))
                    if not block:
                        break
                    size += len(block)
                    if size > limit:
                        raise ConversionError("uncompressed layer exceeds size budget")
                    digest.update(block)
                    target.write(block)
        finally:
            if stream is not raw:
                stream.close()
    if digest.hexdigest() != expected:
        raise ConversionError("uncompressed layer SHA256 does not match config.rootfs.diff_ids")
    check_layer_paths(output)
    return size


def add_bytes(archive, name, data):
    member = tarfile.TarInfo(name)
    member.size, member.mode, member.mtime = len(data), 0o644, 0
    archive.addfile(member, io.BytesIO(data))


def convert(input_path, output_path):
    input_path, output_path = Path(input_path), Path(output_path)
    if input_path.resolve() == output_path.resolve():
        raise ConversionError("input and output must differ")
    if output_path.exists():
        raise ConversionError("output already exists; choose a new output path")
    if not input_path.is_file() or not output_path.parent.is_dir():
        raise ConversionError("input must be a regular file and output parent must exist")
    with tempfile.TemporaryDirectory(prefix="routeros-classic-", dir=output_path.parent) as temporary:
        work = Path(temporary)
        with tarfile.open(input_path, "r:*") as archive:
            members = {}
            for index, member in enumerate(archive):
                if index >= MAX_OUTER_MEMBERS:
                    raise ConversionError("input has too many archive members")
                name = safe_name(member.name)
                if name in members:
                    raise ConversionError("duplicate archive member name")
                if not member.isfile() and not member.isdir():
                    raise ConversionError("outer archive links and special files are unsupported")
                members[name] = member
            _, manifest = metadata(archive, members, "manifest.json")
            if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
                raise ConversionError("exactly one saved image is required")
            image = manifest[0]
            config_bytes, config = metadata(archive, members, image.get("Config"))
            if not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != "arm64" or config.get("variant") not in (None, "", "v8"):
                raise ConversionError("saved image must have one linux/arm64 platform")
            rootfs = config.get("rootfs")
            if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
                raise ConversionError("config.rootfs must use layers")
            diff_ids, layer_names = rootfs.get("diff_ids"), image.get("Layers")
            if not isinstance(diff_ids, list) or not isinstance(layer_names, list) or not layer_names or len(diff_ids) != len(layer_names) or len(layer_names) > 128:
                raise ConversionError("layer list and rootfs.diff_ids are missing or inconsistent")
            tags = image.get("RepoTags")
            if tags is not None and (not isinstance(tags, list) or any(not isinstance(tag, str) or not tag or any(c in tag for c in "\r\n\x00") for tag in tags)):
                raise ConversionError("invalid RepoTags")
            layer_outputs, seen, total = [], set(), 0
            for index, (name, diff_id) in enumerate(zip(layer_names, diff_ids)):
                match = DIGEST.fullmatch(diff_id) if isinstance(diff_id, str) else None
                if match is None:
                    raise ConversionError("invalid rootfs.diff_ids SHA256")
                digest = match.group(1)
                member = regular_member(members, name)
                spool = work / f"layer-{index}.tar"
                size = spool_layer(archive, member, spool, digest, MAX_TOTAL_BYTES - total)
                total += size
                # Repeated identical diff IDs can reference the same output
                # member; verify every original layer before reusing it.
                layer_outputs.append((digest, spool, size))
            config_digest = hashlib.sha256(config_bytes).hexdigest()
            converted = [{"Config": config_digest + ".json", "RepoTags": tags, "Layers": [digest + "/layer.tar" for digest, _, _ in layer_outputs]}]
            temporary_output = work / "classic.tar"
            with tarfile.open(temporary_output, "w", format=tarfile.USTAR_FORMAT) as output:
                add_bytes(output, config_digest + ".json", config_bytes)
                for digest, spool, size in layer_outputs:
                    if digest in seen:
                        continue
                    seen.add(digest)
                    add_bytes(output, digest + "/VERSION", b"1.0")
                    member = tarfile.TarInfo(digest + "/layer.tar")
                    member.size, member.mode, member.mtime = size, 0o644, 0
                    with open(spool, "rb") as stream:
                        output.addfile(member, stream)
                add_bytes(output, "manifest.json", json.dumps(converted, separators=(",", ":")).encode())
            summary = {"input_bytes": input_path.stat().st_size, "output_bytes": temporary_output.stat().st_size,
                       "input_sha256": sha_file(input_path), "output_sha256": sha_file(temporary_output),
                       "layers": len(layer_outputs), "uncompressed_layer_bytes": total, "platform": "linux/arm64"}
            # All validation and hashing finish before publishing a complete
            # archive. No partial output remains after a failed conversion.
            # A hard-link publication also refuses an output created by
            # another process after our initial existence check.
            os.link(temporary_output, output_path)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()
    try:
        result = convert(args.input, args.output)
    except (ConversionError, OSError, tarfile.TarError, EOFError, zlib.error) as exc:
        print("conversion failed: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
