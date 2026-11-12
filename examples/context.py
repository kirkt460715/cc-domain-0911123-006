import json
from pathlib import Path

def load():
    return json.loads((Path(__file__).with_name("context.json")).read_text())

def run():
    from sealvault.service import Vault
    from sealvault.custody import actors, chain
    now = ['2026-11-05T08:00:00Z']
    with Vault(clock=lambda: now[0]) as app:
        for actor, role in [('collector', 'collector'), ('keeper', 'custodian'), ('reviewer', 'custodian')]:
            actors.register(app.db, actor, role)
        for row in load()['records']:
            now[0] = row['created']
            app.cases.create(row['case_id'], '合成保管案件', 'collector')
            obj = app.objects.put(b'local synthetic record')
            app.cases.attach(row['case_id'], 1, 'collector', {'path':'data.txt','digest':obj['digest'],'size':obj['size'],'media_type':'text/plain','metadata':{}})
        now[0] = '2026-11-05T09:00:00Z'
        for case in ['closed','waiting']:
            app.handoffs.propose(case+'-first', case, 'collector', 'keeper', 2, '2026-11-20T00:00:00Z', '合成交接')
        now[0] = '2026-11-05T10:00:00Z'
        app.handoffs.reject('closed-first', 'keeper', '补齐移交说明')
        now[0] = '2026-11-09T02:00:00Z'
        handoff = app.handoffs.propose('closed-second', 'closed', 'collector', 'keeper', 2, '2026-11-20T00:00:00Z', '重新移交')
        app.handoffs.accept('closed-second', 'keeper', handoff['fingerprint'], 'local-receipt')
        case = app.cases.get('closed')
        app.seals.prepare('local-seal', 'closed', case['revision'], 'keeper')
        app.seals.seal('local-seal', 'reviewer', '2027-01-01T00:00:00Z')
        checks = [chain.verify(app.db, c)['valid'] for c in ['closed','waiting']]
        return {'ok': all(checks), 'records': app.db.scalar('SELECT COUNT(*) FROM custody')}


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, sort_keys=True))
