"""Independent BitcoinX validation of the frozen BRC-197 Script and corpus."""
from bitcoinx import Script,Tx,TxOutput,TxInputContext,InterpreterState,InterpreterLimits,MinerPolicy,SigHash,push_item
from pathlib import Path
import gzip,hashlib,json

HERE=Path(__file__).parent
manifest=json.loads((HERE/'artifact.json').read_text())
def sha(b): return hashlib.sha256(b).hexdigest()
def h256(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def assemble(source):
    parts=[]
    for token in source.split():
        parts.append(push_item(bytes.fromhex(token[2:])) if token.startswith('x:') else Script.asm_word_to_bytes(token))
    return b''.join(parts)
programs={}
for name in ('activation','active'):
    art=manifest['programs'][name]
    asm=(HERE/(name+'.asm')).read_text()
    program=bytes.fromhex((HERE/(name+'.hex')).read_text().strip())
    assert sha(asm.encode())==art['assemblyFileSHA256']
    assert assemble(asm)==program
    part_words=[];part_bytes=[];word_start=0;byte_start=0
    for component in art['components']:
        assert component['path'].startswith('components/') and '..' not in component['path']
        source=(HERE/component['path']).read_text()
        words=source.split();wire=assemble(source)
        assert component['wordStart']==word_start and component['wordCount']==len(words)
        assert component['byteStart']==byte_start and component['bytes']==len(wire)
        assert sha(wire)==component['sha256']
        part_words.extend(words);part_bytes.append(wire)
        word_start+=len(words);byte_start+=len(wire)
    assert part_words==asm.split() and b''.join(part_bytes)==program
    assert len(program)==art['bytes'] and sha(program)==art['programSHA256']
    programs[name]=program
    print(name,'assembled',len(program),sha(program))
def lock(metadata,name):
    result=bytes.fromhex('4dcd02')+metadata+b'\x75'+programs[name]
    assert len(result)==manifest['programs'][name]['lockingBytes']
    return result
def limits():
    return InterpreterLimits(MinerPolicy(1048576,128,128*1024*1024,1000000,8),
                             is_genesis_enabled=True,is_consensus=False)
def execute(tx,index,source):
    state=InterpreterState(limits(),TxInputContext(tx,index,source))
    state.evaluate_script(tx.inputs[index].script_sig)
    state.evaluate_script(source.script_pubkey)
    return bool(state.stack[-1])
graph=json.loads((HERE/'lineage-vectors.json').read_text())
genesis=Tx.from_hex(graph['genesis'])
funders=[Tx.from_hex(raw) for raw in graph['funding']]
parents={tx.hash():tx for tx in [genesis,*funders]}
records=graph['records']
assert [r['name'] for r in records]==['activate','purchase','split','payout','retire']
metadata=genesis.outputs[0].script_pubkey.to_bytes()[3:720]
assert len(metadata)==717
assert genesis.outputs[0].script_pubkey.to_bytes()==lock(metadata,'activation')
assert genesis.outputs[0].value==1
for rec in records:
    tx=Tx.from_hex(rec['tx'])
    sources=[]
    for inp in tx.inputs:
        parent=parents[inp.prev_hash]
        source=parent.outputs[inp.prev_idx]
        sources.append(source)
    assert len(sources)==2
    assert sum(x.value for x in sources)-sum(x.value for x in tx.outputs)==rec['fee']
    for index,source in enumerate(sources):
        assert execute(tx,index,source),(rec['name'],index)
    if rec['name']=='activate':
        assert tx.outputs[0].script_pubkey.to_bytes()==lock(metadata,'active')
        assert tx.outputs[0].value==1
    parents[tx.hash()]=tx
    print(rec['name'],'both complete inputs valid','fee',rec['fee'])
def test_negative(filename,stage):
    cases=json.loads(gzip.decompress((HERE/filename).read_bytes()))
    for case in cases:
        tx=Tx.from_hex(case.get('transaction',case.get('tx')))
        script=Script(bytes.fromhex(case.get('locking')))
        unlock=Script(bytes.fromhex(case.get('unlocking',case.get('unlock'))))
        tx.inputs[0].script_sig=unlock
        amount=1 if stage else case['value']
        source=TxOutput(amount,script)
        pre=list(unlock.ops())[case.get('preimageIndex',99 if stage else 0)]
        assert isinstance(pre,bytes)
        assert h256(pre)==tx.signature_hash(0,amount,script,SigHash(0x41)),case['name']
        try:
            accepted=execute(tx,0,source)
        except Exception:
            accepted=False
        assert accepted==case['expected'],case['name']
    print(filename,len(cases),'expected results')
test_negative('negative.json.gz',False)
test_negative('stage_negative.json.gz',True)
malleability_cases=json.loads((HERE/'malleability-negative.json').read_text())
for case in malleability_cases:
    tx=Tx.from_hex(case['transaction'])
    index=case.get('inputIndex',0)
    tx.inputs[index].script_sig=Script(bytes.fromhex(case['unlocking']))
    source=TxOutput(case['value'],Script(bytes.fromhex(case['locking'])))
    pre=list(tx.inputs[index].script_sig.ops())[case.get('preimageIndex',0)]
    assert h256(pre)==tx.signature_hash(index,source.value,source.script_pubkey,SigHash(0x41))
    try: accepted=execute(tx,index,source)
    except Exception: accepted=False
    assert accepted is False,case['name']
print('malleability-negative.json',len(malleability_cases),'expected rejections')
variant=json.loads((HERE/'purchase-variant.json').read_text())
original=Tx.from_hex(variant['original'])
alternatives=[Tx.from_hex(variant[name]) for name in ('variant','listingVariant')]
assert len({tx.hash() for tx in [original,*alternatives]})==3
for alternative in alternatives:
    assert [(o.value,o.script_pubkey.to_bytes()) for o in original.outputs]==[(o.value,o.script_pubkey.to_bytes()) for o in alternative.outputs]
sources=[TxOutput(variant['listingValue'],Script(bytes.fromhex(variant['listingSource']))),
         TxOutput(variant['fundingValue'],Script(bytes.fromhex(variant['fundingSource'])))]
for tx in [original,*alternatives]:
    pre=next(item for item in tx.inputs[0].script_sig.ops() if isinstance(item,bytes) and len(item)>100)
    assert h256(pre).hex()==variant['commitment']
    for index,source in enumerate(sources): assert execute(tx,index,source)
print('purchase txid variants: three complete transactions valid with identical commitment')
maximum=json.loads(gzip.decompress((HERE/'max8-activation.json.gz').read_bytes()))
max_tx=Tx.from_hex(maximum['transaction'])
max_lock=Script(bytes.fromhex(maximum['locking']))
max_tx.inputs[0].script_sig=Script(bytes.fromhex(maximum['unlocking']))
max_genesis=Tx.from_hex(maximum['genesis'])
max_funder=Tx.from_hex(maximum['funding'])
assert max_genesis.outputs[0].script_pubkey.to_bytes()==max_lock.to_bytes()
max_sources=[max_genesis.outputs[0],max_funder.outputs[0]]
assert sum(source.value for source in max_sources)>sum(out.value for out in max_tx.outputs)
for index,source in enumerate(max_sources):
    assert execute(max_tx,index,source),('max8 activation',index)
print('eight-recipient activation valid with complete funding input')
maximum_active=json.loads(gzip.decompress((HERE/'max8-active.json.gz').read_bytes()))
max_parents={Tx.from_hex(raw).hash():Tx.from_hex(raw) for raw in
             [maximum_active['parent'],*maximum_active['funding']]}
for name in ('purchase','payout'):
    tx=Tx.from_hex(maximum_active[name])
    assert len(tx.inputs)==2
    sources=[max_parents[inp.prev_hash].outputs[inp.prev_idx] for inp in tx.inputs]
    assert sum(source.value for source in sources)>sum(out.value for out in tx.outputs)
    for index,source in enumerate(sources):
        assert execute(tx,index,source),(name,index)
    if name=='payout': assert len(tx.outputs)==11
    max_parents[tx.hash()]=tx
print('eight-recipient purchase and payout valid with complete funding inputs')
print('BitcoinX family verification passed')
