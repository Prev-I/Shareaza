import sys,hashlib,pefile,datetime
from asn1crypto import cms, x509
from cryptography import x509 as cx
def certs_of(path):
    data=open(path,'rb').read(); pe=pefile.PE(data=data); sd=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    ci=cms.ContentInfo.load(data[sd.VirtualAddress+8:sd.VirtualAddress+sd.Size])
    return [c.chosen for c in ci['content']['certificates']]
root=x509.Certificate.load(open(sys.argv[1],'rb').read())
print('root', root.subject.human_friendly, 'sha256', hashlib.sha256(root.dump()).hexdigest())
for p in sys.argv[2:]:
    cs=certs_of(p); print('==',p)
    for c in cs:
        x=cx.load_der_x509_certificate(c.dump())
        print(' cert', c.subject.native.get('common_name'), '| issuer', c.issuer.native.get('common_name'), '| EKU', [e.dotted_string for e in x.extensions.get_extension_for_class(cx.ExtendedKeyUsage).value] if any(isinstance(e.value,cx.ExtendedKeyUsage) for e in x.extensions) else None, '| sha256', hashlib.sha256(c.dump()).hexdigest()[:16], x.not_valid_before_utc.date(), x.not_valid_after_utc.date())
        for cand in cs+[root]:
            if cand is c: continue
            try: x.verify_directly_issued_by(cx.load_der_x509_certificate(cand.dump())); print('   issued by (sig ok):', cand.subject.native.get('common_name'))
            except Exception: pass
