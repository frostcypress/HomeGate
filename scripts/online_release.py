#!/usr/bin/env python3
"""Sign a verified HomeGate offline bundle for the online update service."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

PUBLIC_KEY_PATH = 'usr/libexec/homegate/update-public.pem'
PUBLISHER_PUBLIC_KEY = 'packaging/production/update-public.pem'
ARCHIVE_LIMIT = 32 * 1024 * 1024
PACKAGES = ('homegate-core', 'luci-app-homegate', 'luci-i18n-homegate-zh-cn')


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def openssl(*args, data=None):
    return subprocess.run(['openssl', *args], input=data, check=True, stdout=subprocess.PIPE).stdout


def public_key(path):
    with Path(path).open('rb') as file:
        supplied = file.read(4097)
    if len(supplied) > 4096 or not re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+'
                                                rb'-----END PUBLIC KEY-----\r?\n?', supplied):
        raise ValueError('Expected one PEM public key')
    return openssl('pkey', '-pubin', '-pubout', data=supplied)


def describe_bundle(archive, raw):
    match = re.fullmatch(r'homegate-r([1-9][0-9]*)-offline-three\.tar', archive.name)
    if not match or not 0 < len(raw) <= ARCHIVE_LIMIT:
        raise ValueError('Invalid update archive name or size')
    folder = archive.stem
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as payload:
        members = {}
        for member in payload:
            if member.isdir() and member.name == folder:
                continue
            directory, separator, name = member.name.partition('/')
            if not member.isfile() or directory != folder or not separator or '/' in name or name in members or len(members) >= 8:
                raise ValueError('Unexpected update archive member')
            members[name] = member
        member = members.get('SOURCE.json')
        if not member or member.size > 65536:
            raise ValueError('Missing or oversized release receipt')
        source = json.load(payload.extractfile(member))
        version, arch = source['version'], source['architecture']
        previous = int(match[1]) - 1
        if (source['format'] != 'homegate-offline-three-v1' or source.get('source_payload_verified') is not True or
                not re.fullmatch(r'\d+\.\d+\.\d+-r' + match[1], version) or previous < 1 or
                not re.fullmatch(r'[a-z0-9_-]{1,64}', arch) or arch == 'all'):
            raise ValueError('Update bundle does not identify a verified target')
        packages = {f"{name}_{version}_{arch if name == 'homegate-core' else 'all'}.ipk" for name in PACKAGES}
        if set(members) != packages | {'SOURCE.json','SHA256SUMS','installed-SHA256SUMS','install.sh','upgrade-log.sh'}:
            raise ValueError('Expected exactly the three packages and offline migration files')
        checksums = payload.extractfile(members['SHA256SUMS']).read()
        if not 0 < len(checksums) <= 4096:
            raise ValueError('Unexpected offline checksum manifest size')
        hashes = {}
        for line in checksums.decode('ascii').splitlines():
            digest, separator, name = line.partition('  ')
            if not separator or name in hashes or not re.fullmatch(r'[0-9a-f]{64}', digest):
                raise ValueError('Invalid offline checksum manifest')
            hashes[name] = digest
        if set(hashes) != set(members) - {'SHA256SUMS'}:
            raise ValueError('Offline checksum manifest does not cover archive')
        for name, digest in hashes.items():
            if sha256(payload.extractfile(members[name]).read()) != digest:
                raise ValueError('Bundle checksum mismatch: ' + name)
        if source['sha256'] != {name:hashes[name] for name in packages}:
            raise ValueError('Package hashes differ from the build receipt')
        series = version.rsplit('-r', 1)[0]
        minimum = source.get('minimum_version')
        if 'minimum_version' in source:
            allowed = re.fullmatch(re.escape(series) + r'-r([1-9][0-9]{0,8})', minimum) if isinstance(minimum, str) else None
            script = payload.extractfile(members['install.sh']).read()
            declared = re.findall(rb'(?m)^minimum_release=([^\r\n]*)$', script)
            if not allowed or int(allowed[1]) > previous or declared != [allowed[1].encode()]:
                raise ValueError('Offline installer and receipt have different upgrade ranges')
    manifest = {
        'from_version': f'{series}-r{previous}',
        'version': version, 'architecture': arch, 'artifact': archive.name,
        'sha256': sha256(raw), 'size': len(raw),
    }
    if minimum is not None:
        manifest['minimum_version'] = minimum
    return source, manifest


def sign_bundle(archive, key, destination):
    with archive.open('rb') as file:
        raw = file.read(ARCHIVE_LIMIT + 1)
    source, manifest = describe_bundle(archive, raw)
    signer = openssl('pkey', '-in', str(key), '-pubout')
    fingerprint = sha256(signer)
    if source['installed_files_sha256'].get(PUBLIC_KEY_PATH) != fingerprint:
        raise ValueError('Signing key does not match the public key verified in the Core package')
    metadata = (json.dumps(manifest, indent=2) + '\n').encode()
    signature = openssl('dgst', '-sha256', '-sign', str(key), data=metadata)
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp)
        (path/'public.pem').write_bytes(signer)
        (path/'manifest.sig').write_bytes(signature)
        openssl('dgst','-sha256','-verify',str(path/'public.pem'),'-signature',str(path/'manifest.sig'),data=metadata)
    destination.mkdir(mode=0o700)
    (destination/'manifest.json').write_bytes(metadata)
    (destination/'manifest.sig').write_bytes(signature)
    (destination/archive.name).write_bytes(raw)
    offline = destination / archive.name.replace('-offline-three.tar', '-luci-offline.tar')
    with tarfile.open(offline, 'w', format=tarfile.USTAR_FORMAT) as bundle:
        for name, body in (('manifest.json', metadata), ('manifest.sig', signature), (archive.name, raw)):
            member = tarfile.TarInfo(name)
            member.size = len(body)
            bundle.addfile(member, io.BytesIO(body))
    return {**manifest, 'public_key_sha256':fingerprint}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--signing-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(sign_bundle(args.archive, args.signing_key, args.output)))
