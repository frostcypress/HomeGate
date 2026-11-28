"""Persist prior confirmed AAAA ownership in an isolated AliDNS test store."""
import hashlib
from ipaddress import IPv6Address


def seed_managed_aaaa(store,account,key_id,row):
    zone=row['DomainName']
    host=zone if row['RR']=='@' else row['RR']+'.'+zone
    name=hashlib.sha1('\0'.join((account,key_id,zone,host)).encode()).hexdigest()
    directory=store/'aliyun-managed'
    directory.mkdir(mode=0o700,exist_ok=True)
    proof=directory/name
    proof.write_text(row['RecordId']+':'+IPv6Address(row['Value']).exploded+'\n')
    proof.chmod(0o600)
    return proof
