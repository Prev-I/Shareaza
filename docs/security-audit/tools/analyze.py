import sys, hashlib, datetime, pefile
from asn1crypto import cms, x509
def authhash(pe, data, alg):
    h = hashlib.new(alg)
    off = pe.OPTIONAL_HEADER.get_file_offset()
    ck = off+64
    secdir = off + (96 if pe.OPTIONAL_HEADER.Magic==0x10b else 112) + 4*8
    h.update(data[:ck]); h.update(data[ck+4:secdir])
    sd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    end = sd.VirtualAddress if sd.VirtualAddress else len(data)
    h.update(data[secdir+8:end])
    return h.hexdigest()
for path in sys.argv[1:]:
    data = open(path,'rb').read()
    print('==', path, len(data), hashlib.sha256(data).hexdigest())
    try: pe = pefile.PE(data=data)
    except Exception as e: print('  not PE:', e); continue
    print('  machine', hex(pe.FILE_HEADER.Machine), 'ts', datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(), 'dll' if pe.is_dll() else 'exe', 'subsys', pe.OPTIONAL_HEADER.Subsystem, 'linker', pe.OPTIONAL_HEADER.MajorLinkerVersion)
    try:
        for fi in pe.FileInfo:
            for e in fi:
                if hasattr(e,'StringTable'):
                    for st in e.StringTable:
                        print('  ver:', {k.decode(errors='replace'):v.decode(errors='replace') for k,v in st.entries.items() if k in (b'CompanyName',b'FileDescription',b'FileVersion',b'ProductName',b'ProductVersion',b'LegalCopyright',b'OriginalFilename')})
    except Exception as e: print('  no version', e)
    try:
        dbg=[d.entry.PdbFileName.decode(errors='replace').rstrip('\0') for d in pe.DIRECTORY_ENTRY_DEBUG if hasattr(d.entry,'PdbFileName')]; print('  pdb', dbg)
    except Exception: pass
    sd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if not sd.VirtualAddress: print('  Authenticode: NONE'); 
    else:
        blob = data[sd.VirtualAddress+8: sd.VirtualAddress+sd.Size]
        ci = cms.ContentInfo.load(blob)
        sdv = ci['content']
        certs=[c.chosen for c in sdv['certificates']]
        for c in certs: print('  cert subj:', c.subject.human_friendly, '| issuer:', c.issuer.human_friendly, '|', c['tbs_certificate']['validity']['not_before'].native.date(), '->', c['tbs_certificate']['validity']['not_after'].native.date())
        from asn1crypto import core
        raw = sdv['encap_content_info']['content'].contents
        def der(b):
            out=[]; i=0
            while i<len(b):
                t=b[i]; l=b[i+1]; i+=2
                if l&0x80:
                    n=l&0x7f; l=int.from_bytes(b[i:i+n],'big'); i+=n
                out.append((t,b[i:i+l])); i+=l
            return out
        kids=der(raw); dk=der(kids[1][1])
        alg={'2.16.840.1.101.3.4.2.1':'sha256','1.3.14.3.2.26':'sha1','2.16.840.1.101.3.4.2.2':'sha384'}
        oid=der(dk[0][1])[0][1]
        # decode oid
        vals=[oid[0]//40,oid[0]%40]; v=0
        for x in oid[1:]:
            v=(v<<7)|(x&0x7f)
            if not x&0x80: vals.append(v); v=0
        alg=alg.get('.'.join(map(str,vals)),'sha256')
        dg=dk[1][1]
        print('  spc digest', alg, dg.hex(), 'computed', authhash(pe,data,alg), 'MATCH' if dg.hex()==authhash(pe,data,alg) else 'MISMATCH')
        for si in sdv['signer_infos']:
            print('  signer serial', si['sid'].chosen['serial_number'].native if si['sid'].name=='issuer_and_serial_number' else si['sid'])
            for a in si['unsigned_attrs'] or []:
                print('  unsigned attr', a['type'].native)
                if a['type'].native=='microsoft_time_stamp_token':
                    try:
                        tci=cms.ContentInfo.load(a['values'][0].contents if False else a['values'][0].dump())
                        from asn1crypto import tsp
                        ts=tsp.TSTInfo.load(tci['content']['encap_content_info']['content'].contents)
                        print('  timestamp', ts['gen_time'].native)
                    except Exception as e: print('  ts parse err', e)
            # verify signature over signed attrs with leaf cert
            try:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography import x509 as cx
                sid=si['sid'].chosen
                leaf=[c for c in certs if c.serial_number==sid['serial_number'].native][0]
                pub=cx.load_der_x509_certificate(leaf.dump()).public_key()
                sa=si['signed_attrs'].dump(); sa=b'\x31'+sa[1:]
                hn=si['digest_algorithm']['algorithm'].native
                pub.verify(si['signature'].native, sa, padding.PKCS1v15(), getattr(hashes,hn.upper())())
                print('  signature over signed attrs: VALID against', leaf.subject.native.get('common_name'))
                # chain link
                for c in certs:
                    if c is leaf: continue
                    try:
                        cx.load_der_x509_certificate(leaf.dump()).verify_directly_issued_by(cx.load_der_x509_certificate(c.dump())); print('  leaf issued by embedded cert:', c.subject.native.get('common_name'))
                    except Exception: pass
            except Exception as e: print('  sig verify error', repr(e))
    # strings of interest
    import re
    for m in set(re.findall(rb'[A-Za-z]:\\[\x20-\x7e]{4,120}', data)): print('  path-string', m.decode()[:140])
    for m in set(re.findall(rb'https?://[\x20-\x7e]{4,100}', data)): print('  url', m.decode()[:110])
