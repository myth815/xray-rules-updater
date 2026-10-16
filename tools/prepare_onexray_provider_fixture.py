#!/usr/bin/env python3
"""Prepare the synthetic producer/Dart fixture for an offline native Core check.

This does not install files in OneXray, download assets, or validate its adapter.
Only the tracked fixture is accepted; all native DAT bytes come from input.json.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import re
import urllib.parse


def prepare(output: pathlib.Path) -> dict:
    source = pathlib.Path(__file__).resolve().parents[1] / "testdata" / "onexray-provider-geodata"
    fixture = json.loads((source / "input.json").read_bytes())
    provider_bytes = (source / "provider.json").read_bytes()
    provider = json.loads(provider_bytes)
    native = dict(provider)
    metadata = native.pop("geodata")
    expected_native = (source / "native.json").read_bytes()
    # Python integers retain their exact precision. Do not round-trip raw node
    # data through floating point or synthesize a native config from metadata.
    if native != json.loads(expected_native):
        raise ValueError("fixture native policy differs beyond geodata")
    if set(metadata) != {"assets"} or not isinstance(metadata["assets"], list):
        raise ValueError("invalid fixture provider contract")
    original = {
        "ip": base64.b64decode(fixture["geoip_base64"], validate=True),
        "domain": base64.b64decode(fixture["geosite_base64"], validate=True),
    }
    files = {}
    for asset in metadata["assets"]:
        if set(asset) != {"file", "url"}:
            raise ValueError("unexpected provider asset keys")
        match = re.fullmatch(r"home_(geoip|geosite)_([0-9a-f]{64})\.dat", asset["file"])
        if not match or asset["file"] in files:
            raise ValueError("invalid or duplicate content-addressed filename")
        data = original["ip" if match[1] == "geoip" else "domain"]
        digest = hashlib.sha256(data).hexdigest()
        if match[2] != digest:
            raise ValueError("fixture DAT bytes do not match provider SHA256")
        url = urllib.parse.urlsplit(asset["url"])
        if (url.scheme != "https" or url.netloc != "rules.example.invalid"
                or url.query or url.fragment or not re.fullmatch(
                    r"/versions/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/" + match[1] + r"\.dat", url.path)):
            raise ValueError("fixture URL is not an immutable synthetic origin")
        files[asset["file"]] = data
    if not output.exists():
        output.mkdir(mode=0o700, parents=True)
    if not output.is_dir() or output.is_symlink() or any(output.iterdir()):
        raise ValueError("output must be an empty real directory")
    for name, data in {**files, "native.json": expected_native}.items():
        destination = output / name
        with destination.open("xb") as stream:
            stream.write(data)
        destination.chmod(0o600)
    summary = {
        "provider_sha256": hashlib.sha256(provider_bytes).hexdigest(),
        "native_sha256": hashlib.sha256(expected_native).hexdigest(),
        "asset_files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
        "metadata_removed_only": True,
        "downloaded": False,
        "app_validation": False,
    }
    (output / "preparation.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output / "preparation.json").chmod(0o600)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=pathlib.Path, help="empty scratch directory for offline Core input")
    args = parser.parse_args()
    print(json.dumps(prepare(args.output), indent=2))
