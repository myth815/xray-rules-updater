import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("classic_converter", Path(__file__).with_name("docker_save_for_routeros.py"))
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)


def tar_bytes(entries):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w") as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return target.getvalue()


def fixture(path, compressed=True, arch="arm64", layer_path="usr/bin/example", bad_hash=False, duplicate_image=False):
    layer = tar_bytes([(layer_path, b"synthetic executable bytes")])
    diff = hashlib.sha256(layer).hexdigest()
    config = json.dumps({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": ["sha256:" + ("0" * 64 if bad_hash else diff)]}}).encode()
    stored_layer = gzip.compress(layer) if compressed else layer
    layer_name = "blobs/sha256/" + hashlib.sha256(stored_layer).hexdigest()
    config_name = "blobs/sha256/" + hashlib.sha256(config).hexdigest()
    manifest = [{"Config": config_name, "RepoTags": ["example/fixture:v1"], "Layers": [layer_name]}]
    if duplicate_image:
        manifest.append(manifest[0])
    path.write_bytes(tar_bytes([(config_name, config), (layer_name, stored_layer), ("manifest.json", json.dumps(manifest).encode()),
                               ("index.json", b'{"schemaVersion":2}'), ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')]))
    return config, layer


class ConverterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.output = self.root / "input.tar", self.root / "classic.tar"

    def test_gzip_and_plain_layers_preserved_exactly(self):
        for compressed in (True, False):
            with self.subTest(compressed=compressed):
                config, layer = fixture(self.source, compressed=compressed)
                output = self.root / ("gzip.tar" if compressed else "plain.tar")
                summary = converter.convert(self.source, output)
                self.assertEqual(summary["platform"], "linux/arm64")
                self.assertEqual(summary["layers"], 1)
                self.assertEqual(summary["output_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
                with tarfile.open(output) as archive:
                    names = archive.getnames()
                    self.assertNotIn("index.json", names)
                    self.assertNotIn("oci-layout", names)
                    manifest = json.load(archive.extractfile("manifest.json"))
                    self.assertEqual(manifest[0]["RepoTags"], ["example/fixture:v1"])
                    self.assertEqual(archive.extractfile(manifest[0]["Config"]).read(), config)
                    self.assertEqual(archive.extractfile(manifest[0]["Layers"][0]).read(), layer)
                self.assertEqual(summary["uncompressed_layer_bytes"], len(layer))

    def test_rejects_multiple_images_and_wrong_platform(self):
        for kwargs in ({"duplicate_image": True}, {"arch": "amd64"}):
            with self.subTest(kwargs=kwargs):
                fixture(self.source, **kwargs)
                with self.assertRaises(converter.ConversionError):
                    converter.convert(self.source, self.output)
                self.assertFalse(self.output.exists())

    def test_rejects_bad_diff_id_and_layer_expansion(self):
        fixture(self.source, bad_hash=True)
        with self.assertRaisesRegex(converter.ConversionError, "SHA256"):
            converter.convert(self.source, self.output)
        self.assertFalse(self.output.exists())
        fixture(self.source)
        with mock.patch.object(converter, "MAX_LAYER_BYTES", 64):
            with self.assertRaisesRegex(converter.ConversionError, "size budget"):
                converter.convert(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["input.tar"])

    def test_rejects_outer_and_inner_path_traversal(self):
        for name in ("../escape", "/absolute", "a/../../escape", "a\\b"):
            with self.subTest(name=name):
                fixture(self.source, layer_path=name)
                with self.assertRaises(converter.ConversionError):
                    converter.convert(self.source, self.output)
                self.assertFalse(self.output.exists())
        self.source.write_bytes(tar_bytes([("../escape", b"x")]))
        with self.assertRaises(converter.ConversionError):
            converter.convert(self.source, self.output)

    def test_rejects_duplicate_outer_members_and_missing_config(self):
        self.source.write_bytes(tar_bytes([("manifest.json", b"[]"), ("manifest.json", b"[]")]))
        with self.assertRaisesRegex(converter.ConversionError, "duplicate"):
            converter.convert(self.source, self.output)
        self.source.write_bytes(tar_bytes([("manifest.json", b'[{"Config":"missing","Layers":["missing"]}]')]))
        with self.assertRaisesRegex(converter.ConversionError, "missing"):
            converter.convert(self.source, self.output)

    def test_rejects_escaping_layer_links(self):
        layer = self.root / "links.tar"
        for target in ("../../escape", "/absolute"):
            with tarfile.open(layer, "w") as archive:
                member = tarfile.TarInfo("usr/link")
                member.type, member.linkname = tarfile.SYMTYPE, target
                archive.addfile(member)
            with self.assertRaises(converter.ConversionError):
                converter.check_layer_paths(layer)

    def test_refuses_existing_output_and_identical_input(self):
        fixture(self.source)
        self.output.write_bytes(b"preserve existing artifact")
        with self.assertRaises(converter.ConversionError):
            converter.convert(self.source, self.output)
        self.assertEqual(self.output.read_bytes(), b"preserve existing artifact")
        with self.assertRaises(converter.ConversionError):
            converter.convert(self.source, self.source)


if __name__ == "__main__":
    unittest.main()
