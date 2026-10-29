#!/usr/bin/env python3
"""Integration tests: temporary keys, OpenSSL interoperability, CLI failures.
Never launches Navicat or changes its preferences. Optional --source-app is read only.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import struct
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'zig-out/bin/lejav-gen-navicat')
parser.add_argument('--openssl', default='/opt/homebrew/opt/openssl@3/bin/openssl')
parser.add_argument('--source-app', type=Path)
parser.add_argument('--build-copy', action='store_true', help='Test copy and in-place workflows on disposable apps; requires --source-app and Navicat closed')
parser.add_argument('--prepared-app', type=Path)
parser.add_argument('--prepared-key', type=Path)
args = parser.parse_args()
if args.build_copy and not args.source_app:
    parser.error('--build-copy requires --source-app')
binary = str(args.binary.resolve())
checks = 0


def run(*argv, ok=True, data=None, cwd=None):
    global checks
    result = subprocess.run([str(x) for x in argv], input=data, capture_output=True, cwd=cwd)
    if ok:
        assert result.returncode == 0, (argv, result.returncode, result.stderr.decode(errors='replace'))
    else:
        assert result.returncode != 0, argv
    checks += 1
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_local_signature(app):
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
    claims = plistlib.loads(run('/usr/bin/codesign', '-d', '--entitlements', '-', '--xml', app))
    restricted = {'com.apple.application-identifier', 'application-identifier',
                  'com.apple.developer.team-identifier', 'com.apple.security.application-groups',
                  'keychain-access-groups'}
    assert not restricted.intersection(claims), claims
    assert claims.get('com.apple.security.cs.allow-jit') is True
    manifest = json.loads((app / 'Contents/Resources/lejav-gen-navicat-patch.json').read_text())
    assert manifest['signing_revision'] == 1


with tempfile.TemporaryDirectory(prefix='lejav-gen-navicat mac test ') as directory:
    root = Path(directory)
    key = root / 'private.pem'
    public = root / 'public.pem'
    run(binary, 'keygen', '--out', key)
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    before = digest(key)
    run(binary, 'keygen', '--out', key, ok=False)
    assert digest(key) == before
    protected = root / 'unrelated.txt'
    protected.write_text('must stay unchanged')
    link = root / 'linked.pem'
    link.symlink_to(protected)
    run(binary, 'keygen', '--out', link, '--force')
    assert not link.is_symlink() and protected.read_text() == 'must stay unchanged'
    assert stat.S_IMODE(link.stat().st_mode) == 0o600
    run(args.openssl, 'pkey', '-in', key, '-pubout', '-out', public)
    serial = run(binary, 'serial', '--version', '18').decode().strip().replace('-', '')
    assert len(serial) == 16 and serial.startswith('NAV')
    request = json.dumps({'K': serial, 'DI': 'mac-test-device', 'P': 'MAC'}, separators=(',', ':')).encode()
    cipher = run(args.openssl, 'pkeyutl', '-encrypt', '-pubin', '-inkey', public,
                 '-pkeyopt', 'rsa_padding_mode:pkcs1', data=request)
    encoded = base64.encodebytes(cipher)
    request_path = root / 'request with spaces.txt'
    request_path.write_bytes(encoded)
    response = run(binary, 'sign', '--request', '@' + str(request_path), '--key', key,
                   '--name', '张"三', '--org', '测试公司').strip()
    signed = base64.b64decode(response, validate=True)
    assert len(signed) == 256
    recovered = run(args.openssl, 'pkeyutl', '-verifyrecover', '-pubin', '-inkey', public,
                    '-pkeyopt', 'rsa_padding_mode:pkcs1', data=signed)
    payload = json.loads(recovered)
    assert list(payload) == ['K', 'DI', 'N', 'O', 'T']
    assert payload['K'] == serial and payload['DI'] == 'mac-test-device'
    assert payload['N'] == '张"三' and payload['O'] == '测试公司'
    assert abs(payload['T'] - time.time()) < 30
    run(binary, 'sign', '--request', '@' + str(request_path), '--key', link,
        '--name', 'n', '--org', 'o', ok=False)
    run(binary, 'sign', '--request', 'not base64', '--key', key, '--name', 'n', '--org', 'o', ok=False)
    run(binary, 'serial', '--version', '15', ok=False)
    run(binary, 'patch', '--out', '--dry-run', ok=False)
    run(binary, 'patch', '--overwrite', ok=False)
    run(binary, 'patch', ok=False)
    run(binary, 'activate', ok=False)  # no interactive terminal, no side effects

    # An unknown but structurally valid ARM64 app must not create output or a stage.
    fake = root / 'unknown.app'
    (fake / 'Contents/Frameworks').mkdir(parents=True)
    (fake / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'com.navicat.NavicatPremium'}))
    header = struct.pack('<8I', 0xfeedfacf, 0x0100000c, 0, 6, 0, 0, 0, 0)
    (fake / 'Contents/Frameworks/libcc.dylib').write_bytes(header)
    target = root / 'output.app'
    run(binary, 'patch', '--app', fake, '--key', key, '--out', target, ok=False)
    assert not target.exists() and not list(root.glob('.lejav-gen-navicat-stage-*'))
    new_key = root / 'must-not-create.pem'
    run(binary, 'activate', '--app', fake, '--key', new_key, '--out', target, '--prepare-only', ok=False)
    assert not new_key.exists() and not target.exists()
    run(binary, 'activate', '--out', fake, '--key', new_key, '--prepare-only', ok=False)
    assert not new_key.exists()
    fake_hash = digest(fake / 'Contents/Frameworks/libcc.dylib')
    run(binary, 'activate', '--app', fake, '--key', new_key, '--prepare-only', ok=False)
    assert digest(fake / 'Contents/Frameworks/libcc.dylib') == fake_hash
    assert not new_key.exists() and not list(root.glob('*.original-backup-*'))


    # A library symlink to outside the bundle must be rejected before writes.
    external = root / 'outside.dylib'
    external.write_bytes(header)
    lib = fake / 'Contents/Frameworks/libcc.dylib'
    lib.unlink()
    lib.symlink_to(external)
    run(binary, 'patch', '--app', fake, '--key', key, '--out', target, ok=False)
    assert external.read_bytes() == header and not target.exists()

    if args.source_app:
        original = args.source_app / 'Contents/Frameworks/libcc.dylib'
        original_hash = digest(original)
        run(binary, 'patch', '--app', args.source_app, '--key', key, '--out', target, '--dry-run')
        assert not target.exists() and digest(original) == original_hash
        occupied = root / 'occupied.app'
        occupied.mkdir()
        run(binary, 'patch', '--app', args.source_app, '--key', key, '--out', occupied, ok=False)
        assert not list(occupied.iterdir())
        dangling = root / 'dangling.app'
        dangling.symlink_to(root / 'missing.app')
        run(binary, 'patch', '--app', args.source_app, '--key', key, '--out', dangling, ok=False)
        assert dangling.is_symlink()
        if args.build_copy:
            run(binary, 'patch', '--app', args.source_app, '--key', key, '--out', target)
            check_local_signature(target)
            run(binary, 'status', '--app', target, '--key', key)
            assert digest(original) == original_hash
            assert not list(root.glob('.lejav-gen-navicat-stage-*'))
            assert not list(root.glob('.lejav-gen-navicat-entitlements-*'))

            # Exercise in-place replacement only on a disposable original.
            installed = root / 'installed.app'
            run('/usr/bin/ditto', args.source_app, installed)
            installed_lib = installed / 'Contents/Frameworks/libcc.dylib'
            original_inode = installed.stat().st_ino
            original_main_hash = digest(installed / 'Contents/MacOS/Navicat Premium')
            inside_key = installed / 'Contents/must-not-create.pem'
            run(binary, 'activate', '--app', installed, '--key', inside_key, '--prepare-only', ok=False)
            assert not inside_key.exists() and digest(installed_lib) == original_hash
            alias = root / 'alias.app'
            alias.symlink_to(installed)
            run(binary, 'activate', '--app', alias, '--key', key, '--prepare-only', ok=False)
            assert alias.is_symlink() and installed.stat().st_ino == original_inode

            # An executable with Navicat's process name checks the running-app guard.
            sleeper = root / 'Navicat Premium'
            shutil.copy('/bin/sleep', sleeper)
            process = subprocess.Popen([str(sleeper), '60'])
            try:
                for _ in range(50):
                    pids = subprocess.run(['/usr/bin/pgrep', '-x', 'Navicat Premium'], capture_output=True)
                    if str(process.pid).encode() in pids.stdout.split():
                        break
                    time.sleep(0.02)
                else:
                    raise AssertionError('Test process not visible to pgrep')
                run(binary, 'activate', '--app', installed, '--key', key, '--prepare-only', ok=False)
                assert installed.stat().st_ino == original_inode
                assert not list(root.glob('installed.app.original-backup-*'))
            finally:
                process.terminate()
                process.wait(timeout=5)

            run(binary, 'activate', '--app', installed, '--key', key, '--prepare-only')
            backups = list(root.glob('installed.app.original-backup-*'))
            assert len(backups) == 1
            backup = backups[0] / 'installed.app'
            assert backup.stat().st_ino == original_inode
            assert digest(backup / 'Contents/Frameworks/libcc.dylib') == original_hash
            assert digest(backup / 'Contents/MacOS/Navicat Premium') == original_main_hash
            assert not (backup / 'Contents/Resources/lejav-gen-navicat-patch.json').exists()
            check_local_signature(installed)
            assert b'Activation: Not inferred' in run(binary, 'status', '--app', installed, '--key', key)
            installed_inode = installed.stat().st_ino
            installed_time = installed_lib.stat().st_mtime_ns
            for _ in range(2):
                run(binary, 'activate', '--app', installed, '--key', key, '--prepare-only', cwd=root)
            run(binary, 'activate', '--app', installed, '--key', link, '--prepare-only', ok=False)
            run(binary, 'activate', '--app', installed, '--key', new_key, '--prepare-only', ok=False)
            assert installed.stat().st_ino == installed_inode and installed_lib.stat().st_mtime_ns == installed_time
            assert list(root.glob('installed.app.original-backup-*')) == backups
            assert not new_key.exists() and digest(original) == original_hash

    if args.prepared_app and args.prepared_key:
        app = args.prepared_app.resolve()
        prepared_key = args.prepared_key.resolve()
        lib = app / 'Contents/Frameworks/libcc.dylib'
        key_hash, lib_hash = digest(prepared_key), digest(lib)
        key_time, lib_time = prepared_key.stat().st_mtime_ns, lib.stat().st_mtime_ns
        check_local_signature(app)
        for _ in range(2):
            run(binary, 'activate', '--out', app, '--key', prepared_key, '--prepare-only', cwd=root)
        run(binary, 'activate', '--out', app, '--key', key, '--prepare-only', ok=False, cwd=root)
        assert digest(prepared_key) == key_hash and digest(lib) == lib_hash
        assert prepared_key.stat().st_mtime_ns == key_time and lib.stat().st_mtime_ns == lib_time

print(f'PASS: {checks} subprocess checks; RSA, UTF-8, permissions, no-overwrite, symlinks, version rejection, dry run, local signatures and selected app preparation workflows.')
