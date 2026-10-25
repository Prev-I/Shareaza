import json,urllib.request,re,sys
pk=[]
for f in sys.argv[1:]:
    pk+=re.findall(r'id="([^"]+)" version="([^"]+)"',open(f,encoding='utf-8-sig').read())
def get(u):
    return json.load(urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'audit'}),timeout=30))
for pid,ver in pk:
    low=pid.lower(); out={'id':pid,'ver':ver}
    try:
        s=get(f'https://azuresearch-usnc.nuget.org/query?q=packageid:{pid}&prerelease=true&semVerLevel=2.0.0&take=1')['data']
        if s:
            d=s[0]; out.update(owners=d.get('owners'),authors=d.get('authors'),verified=d.get('verified'),totalDownloads=d.get('totalDownloads'),projectUrl=d.get('projectUrl'),title=d.get('title'))
            v=[x for x in d['versions'] if x['version']==ver]
            out['verDownloads']=v[0]['downloads'] if v else None
    except Exception as e: out['searcherr']=str(e)
    try:
        r=get(f'https://api.nuget.org/v3/registration5-semver1/{low}/index.json')
        items=[]
        for pg in r['items']:
            if 'items' not in pg: pg=get(pg['@id'])
            items+=pg['items']
        e=[i['catalogEntry'] for i in items if i['catalogEntry']['version']==ver]
        if e:
            e=e[0]; out.update(published=e.get('published'),cat_authors=e.get('authors'),cat_projectUrl=e.get('projectUrl'),licenseExpression=e.get('licenseExpression'),licenseUrl=e.get('licenseUrl'),listed=e.get('listed'),desc=(e.get('description') or '')[:120],tags=e.get('tags'))
        out['nversions']=len(items)
    except Exception as ex: out['regerr']=str(ex)
    print(json.dumps(out))
