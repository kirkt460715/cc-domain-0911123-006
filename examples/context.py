import json
from pathlib import Path

def load():
    return json.loads((Path(__file__).with_name("context.json")).read_text())

def build():
    """Replay the synthetic custody drill through the product interfaces.

    Returns the live Vault and its injected clock so process analytics can be
    run against the same local records. The vault is opened in-memory and the
    fixture contains no real evidence.
    """
    from sealvault.service import Vault
    from sealvault.custody import actors
    now = ['2026-11-05T08:00:00Z']
    vault = Vault(clock=lambda: now[0])
    for actor, role in [('collector', 'collector'), ('keeper', 'custodian'), ('reviewer', 'custodian')]:
        actors.register(vault.db, actor, role)
    for row in load()['records']:
        now[0] = row['created']
        vault.cases.create(row['case_id'], '合成保管案件', 'collector')
        obj = vault.objects.put(b'local synthetic record')
        vault.cases.attach(row['case_id'], 1, 'collector', {'path':'data.txt','digest':obj['digest'],'size':obj['size'],'media_type':'text/plain','metadata':{}})
    now[0] = '2026-11-05T09:00:00Z'
    for case in ['closed','waiting']:
        vault.handoffs.propose(case+'-first', case, 'collector', 'keeper', 2, '2026-11-20T00:00:00Z', '合成交接')
    now[0] = '2026-11-05T10:00:00Z'
    vault.handoffs.reject('closed-first', 'keeper', '补齐移交说明')
    now[0] = '2026-11-09T02:00:00Z'
    handoff = vault.handoffs.propose('closed-second', 'closed', 'collector', 'keeper', 2, '2026-11-20T00:00:00Z', '重新移交')
    vault.handoffs.accept('closed-second', 'keeper', handoff['fingerprint'], 'local-receipt')
    case = vault.cases.get('closed')
    vault.seals.prepare('local-seal', 'closed', case['revision'], 'keeper')
    vault.seals.seal('local-seal', 'reviewer', '2027-01-01T00:00:00Z')
    return vault, now

def run():
    from sealvault.custody import chain
    vault, _ = build()
    try:
        checks = [chain.verify(vault.db, c)['valid'] for c in ['closed','waiting']]
        return {'ok': all(checks), 'records': vault.db.scalar('SELECT COUNT(*) FROM custody')}
    finally:
        vault.close()


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, sort_keys=True))
