"""Opt-in HTTP integration probe for the documented isolated Nginx fixture.

This is separate from default unit tests: it requires a running loopback-only
fixture, never production, and does not launch or reconfigure a server itself.
"""
import http.client
import os
import unittest
import urllib.parse

CURRENT = 'test-v1'
PREVIOUS = 'test-v0'
BODIES = {'geoip.dat': b'current-ip-fixture\n', 'geosite.dat': b'current-site-fixture\n'}
OLD_BODY = b'previous-site-fixture\n'


class VersionedAssetProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = os.environ.get('VERSIONED_ASSET_TEST_URL')
        if not raw:
            raise unittest.SkipTest('requires an explicitly started isolated fixture')
        cls.url = urllib.parse.urlsplit(raw)
        if cls.url.scheme != 'http' or cls.url.hostname != '127.0.0.1' or cls.url.path not in ('', '/'):
            raise ValueError('probe permits only an HTTP IPv4 loopback fixture')

    def request(self, path, method='GET', headers=None, source='127.0.0.1'):
        conn = http.client.HTTPConnection(self.url.hostname, self.url.port or 80, timeout=3, source_address=(source, 0))
        try:
            conn.request(method, path, headers=headers or {})
            r = conn.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            conn.close()

    def test_current_dat_bytes_and_headers(self):
        for filename, expected in BODIES.items():
            with self.subTest(filename=filename):
                status, headers, body = self.request(f'/versions/{CURRENT}/{filename}')
                self.assertEqual((status, body), (200, expected))
                self.assertEqual(headers['X-Rules-Version'], CURRENT)
                self.assertEqual(headers['Content-Type'], 'application/octet-stream')
                self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
                self.assertIn('immutable', headers['Cache-Control'])

    def test_previous_version_uses_its_own_header(self):
        status, headers, body = self.request(f'/versions/{PREVIOUS}/geosite.dat')
        self.assertEqual((status, body), (200, OLD_BODY))
        self.assertEqual(headers['X-Rules-Version'], PREVIOUS)

    def test_head(self):
        status, headers, body = self.request(f'/versions/{CURRENT}/geoip.dat', 'HEAD')
        self.assertEqual((status, body), (200, b''))
        self.assertEqual(int(headers['Content-Length']), len(BODIES['geoip.dat']))

    def test_range(self):
        status, headers, body = self.request(f'/versions/{CURRENT}/geoip.dat', headers={'Range': 'bytes=2-5'})
        self.assertEqual((status, body), (206, BODIES['geoip.dat'][2:6]))
        self.assertEqual(headers['Content-Range'], f'bytes 2-5/{len(BODIES["geoip.dat"])}')

    def test_missing_version(self):
        self.assertEqual(self.request('/versions/not-present/geoip.dat')[0], 404)

    def test_file_allowlist(self):
        for filename in ['onexray.json', 'manifest.json', 'geoip.dat.json', 'apply.sh', 'geoip.dat/extra', '']:
            with self.subTest(filename=filename):
                self.assertEqual(self.request(f'/versions/{CURRENT}/{filename}')[0], 404)

    def test_stage_and_oversized_identifiers(self):
        for version in ['.stage', '_hidden', 'a' * 65]:
            with self.subTest(version=version):
                self.assertEqual(self.request(f'/versions/{version}/geoip.dat')[0], 404)

    def test_path_traversal_cannot_read_a_sentinel(self):
        for path in ['/versions/test-v1/%2e%2e/%2e%2e/secrets/geoip.dat', '/versions/test-v1/geoip.dat%2f..%2f..%2fsecrets%2fgeoip.dat']:
            with self.subTest(path=path):
                status, _, body = self.request(path)
                self.assertNotEqual(status, 200)
                self.assertNotIn(b'OUTSIDE-PUBLICATION-SENTINEL', body)

    def test_file_and_directory_symlinks_are_denied(self):
        for version in ['symlink-file', 'symlink-dir']:
            with self.subTest(version=version):
                status, _, body = self.request(f'/versions/{version}/geoip.dat')
                self.assertIn(status, (403, 404))
                self.assertNotIn(b'OUTSIDE-PUBLICATION-SENTINEL', body)

    def test_server_acl_is_inherited(self):
        status, _, body = self.request(f'/versions/{CURRENT}/geoip.dat', source='127.0.0.2')
        self.assertEqual(status, 403)
        self.assertNotEqual(body, BODIES['geoip.dat'])


if __name__ == '__main__':
    unittest.main()
