import glob, json
names = ['open-ssh-sg-demo','all-ports-open-sg','default (sg-078c6a3bcf2424816)']
files=sorted(glob.glob('reports/*.json'))
for f in files:
    with open(f) as fh:
        data = json.load(fh)
    for r in data:
        res = r.get('resource') or r.get('Resource') or ''
        for n in names:
            if n in res:
                print(f, res, r.get('type') or r.get('Type'), r.get('issue') or r.get('Issue'), r.get('severity') or r.get('Severity'))
