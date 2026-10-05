from bitcoinx import Tx,TxInput,TxOutput,TxInputContext,InterpreterState,InterpreterLimits,MinerPolicy,PrivateKey,Script,SigHash,push_item,int_to_item
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import hashlib,hmac,json,gzip
from pathlib import Path

P=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
R2=int('c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',16)
R3=int('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',16)
INVOICE=b'2-3241645161d8-brc197 authority'
META_LEN=717
ENTRY=157
PROOF_NAMES=range(99)
HERE=Path(__file__).parent
ACTIVE_PROGRAM=bytes.fromhex((HERE/'active.hex').read_text().strip())
STAGE_PROGRAM=bytes.fromhex((HERE/'activation.hex').read_text().strip())
def pushnum(value): return 'OP_'+str(value) if 0<=value<=16 else str(value) if value<=2147483647 else 'x:'+int_to_item(value).hex()
def assemble(asm):
    parts=[]
    for word in asm.split():
        parts.append(push_item(bytes.fromhex(word[2:])) if word.startswith('x:') else Script.asm_word_to_bytes(word))
    return Script(b''.join(parts))

def h256(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def u32(v): return v.to_bytes(4,'little')
def u64(v): return v.to_bytes(8,'little')
def csize(v): return bytes([v]) if v<253 else b'\xfd'+v.to_bytes(2,'little')
def hash160(b): return hashlib.new('ripemd160',hashlib.sha256(b).digest()).digest()
def p2pkh(pub): return Script(bytes.fromhex('76a914')+hash160(pub)+bytes.fromhex('88ac'))
def sig(k,z,d):
    r=PrivateKey.from_int(k).public_key.to_point()[0]%N
    s=pow(k,-1,N)*(z+r*d)%N
    return encode_dss_signature(r,min(s,N-s))+b'\x41'
def derive(d):
    root=PrivateKey.from_int(d).public_key
    t=int.from_bytes(hmac.new(root.to_bytes(compressed=True),INVOICE,hashlib.sha256).digest(),'big')%N
    return root,PrivateKey.from_int((d+t)%N).public_key,PrivateKey.from_int(t).public_key,t
def link(R,Q,D,t,z):
    xr,yr=R.to_point();xq,yq=Q.to_point();xd,yd=D.to_point()
    L=(yq+yr)*pow((xq-xr)%P,-1,P)%P
    return [D.to_bytes(compressed=True),t,sig(2,z,t),sig(3,z,t),xr,yr,xq,yq,L,xd,yd]
def unlock(vals): return assemble(' '.join('x:'+v.hex() if isinstance(v,bytes) else pushnum(v) for v in vals))
def preimage(tx,index,source):
    prevouts=b''.join(i.prev_hash+u32(i.prev_idx) for i in tx.inputs)
    seq=b''.join(u32(i.sequence) for i in tx.inputs)
    outs=b''.join(u64(o.value)+csize(len(o.script_pubkey.to_bytes()))+o.script_pubkey.to_bytes() for o in tx.outputs)
    inp=tx.inputs[index]
    locking=source.script_pubkey.to_bytes()
    pre=(u32(tx.version)+h256(prevouts)+h256(seq)+inp.prev_hash+u32(inp.prev_idx)+csize(len(locking))+locking+
         u64(source.value)+u32(inp.sequence)+h256(outs)+u32(tx.locktime)+u32(0x41))
    assert h256(pre)==tx.signature_hash(index,source.value,source.script_pubkey,SigHash(0x41))
    return pre,prevouts,int.from_bytes(h256(pre),'big')%N
def receipt(op,listing_id,payout=0,n=0,commitment=bytes(32)):
    body=b'ROSL\x01'+bytes([op])+listing_id+u32(1)+u32(n)+u64(payout)+commitment
    assert len(body)==86
    return Script(bytes.fromhex('006a4c56')+body)
def payment_outputs(units):
    items=[TxOutput(units*w,p2pkh(Q.to_bytes(compressed=True))) for Q,w in [(r1[1],2),(r2[1],1)]]
    wire=b''.join(u64(o.value)+b'\x19'+o.script_pubkey.to_bytes() for o in items)
    return items,hashlib.sha256(wire).digest()

seller=derive(41);r1=derive(42);r2=derive(43)
buyer=PrivateKey.from_int(44).public_key
funder=PrivateKey.from_int(45)
fundpub=funder.public_key.to_bytes(compressed=True)
changehash=hash160(fundpub)
change_script=p2pkh(fundpub)
listing_id=b'\x11'*32;terms=b'\x22'*32
meta=bytearray(META_LEN)
meta[:6]=b'ROSL\x01\x01';meta[6:38]=listing_id;meta[38:70]=terms
meta[70:78]=u64(1001);meta[78:86]=u64(1);meta[86:90]=u32(123456)
meta[90:123]=seller[0].to_bytes(compressed=True);meta[123:156]=seller[1].to_bytes(compressed=True)
meta[156]=2
for i,(der,w) in enumerate([(r1,2),(r2,1)]):
    k=ENTRY+i*70
    meta[k:k+33]=der[0].to_bytes(compressed=True)
    meta[k+33:k+66]=der[1].to_bytes(compressed=True)
    meta[k+66:k+70]=u32(w)
active=Script(push_item(bytes(meta))+b'\x75'+ACTIVE_PROGRAM)
stage=Script(push_item(bytes(meta))+b'\x75'+STAGE_PROGRAM)

genesis=Tx(2,[TxInput(bytes([0xbb])*32,0,Script(),0xffffffff)],[TxOutput(1,stage)],0)
def fund(label):
    tx=Tx(2,[TxInput(hashlib.sha256(label.encode()).digest(),0,Script(),0xffffffff)],
          [TxOutput(10000,change_script)],0)
    return tx
def make_tx(parent,index,outputs,label,sequence=0xffffffff,locktime=0):
    ft=fund(label)
    tx=Tx(2,[TxInput(parent.hash(),index,Script(),sequence),TxInput(ft.hash(),0,Script(),0xffffffff)],outputs,locktime)
    return tx,ft
def listing_unlock(tx,source,op,units=0,admin=False,acq=b'\x33'*32,request=b'\x44'*32,
                   change_amount=0,proof_identities=None):
    pre,prevouts,z=preimage(tx,0,source)
    if op==0:
        proofs=[]
        identities=(seller,r1,r2) if proof_identities is None else proof_identities
        for R,Q,D,t in identities:proofs+=link(R,Q,D,t,z)
        proofs += [0]*((9-len(identities))*11)
        assert len(proofs)==len(PROOF_NAMES)
    else: proofs=[]
    adminsig=PrivateKey.from_int((41+seller[3])%N).sign(pre,hasher=h256)+b'\x41' if admin else b''
    buyer_fields=[acq,request,buyer.to_bytes(compressed=True),*buyer.to_point()] if op==1 else [bytes(32),bytes(32),bytes(33),0,0]
    vals=proofs+[pre,prevouts,op,*buyer_fields,
                 units,changehash,change_amount,adminsig,z,sig(2,z,1),sig(3,z,1)]
    tx.inputs[0].script_sig=unlock(vals)
def funding_unlock(tx,source):
    digest=tx.signature_hash(1,source.value,source.script_pubkey,SigHash(0x41))
    tx.inputs[1].script_sig=Script(push_item(funder.sign(digest,hasher=None)+b'\x41')+push_item(fundpub))
def verify(tx,sources,label):
    limits=InterpreterLimits(MinerPolicy(1048576,128,128*1024*1024,1000000,8),is_genesis_enabled=True,is_consensus=False)
    for i,source in enumerate(sources):
        state=InterpreterState(limits,TxInputContext(tx,i,source))
        state.evaluate_script(tx.inputs[i].script_sig);state.evaluate_script(source.script_pubkey)
        assert state.stack[-1],(label,i)
    sum_in=sum(x.value for x in sources);sum_out=sum(x.value for x in tx.outputs)
    assert sum_in>sum_out,(label,sum_in,sum_out)
    print(label,'inputs',len(sources),'outputs',len(tx.outputs),'fee',sum_in-sum_out,'txid',tx.hex_hash())
    records.append(dict(name=label,tx=tx.to_hex(),sources=[dict(txid=tx.inputs[i].prev_hash.hex(),index=tx.inputs[i].prev_idx,
        value=s.value,locking=s.script_pubkey.to_bytes().hex()) for i,s in enumerate(sources)],fee=sum_in-sum_out))

records=[]
# Activation converts the seller-authorized reserve-only stage into the active
# listing after verifying seller and both recipient BRC-42 child links.
activation,af=make_tx(genesis,0,[TxOutput(1,active),TxOutput(9990,change_script)],'activate')
listing_unlock(activation,genesis.outputs[0],0,change_amount=9990)
funding_unlock(activation,af.outputs[0]);verify(activation,[genesis.outputs[0],af.outputs[0]],'activate')

purchase_receipt=Script(bytes.fromhex('006a4ca7')+b'ROSL\x01\x01'+listing_id+b'\x33'*32+b'\x44'*32+
    buyer.to_bytes(compressed=True)+terms)
purchase,pf=make_tx(activation,0,[TxOutput(1002,active),TxOutput(1,purchase_receipt),TxOutput(8990,change_script)],'purchase')
listing_unlock(purchase,activation.outputs[0],1,change_amount=8990)
funding_unlock(purchase,pf.outputs[0]);verify(purchase,[activation.outputs[0],pf.outputs[0]],'purchase')

# A third party can change the funding input's unlocking Script without changing
# either SIGHASH_ALL|FORKID preimage. Both complete transactions remain valid.
purchase_variant=Tx.from_hex(purchase.to_hex())
purchase_variant.inputs[1].script_sig=Script(b'\x00'+purchase.inputs[1].script_sig.to_bytes())
listing_variant=Tx.from_hex(purchase.to_hex())
listing_variant.inputs[0].script_sig=Script(b'\x00\x75'+purchase.inputs[0].script_sig.to_bytes())
assert purchase_variant.hash()!=purchase.hash()
assert listing_variant.hash() not in (purchase.hash(),purchase_variant.hash())
assert [o.value for o in purchase_variant.outputs]==[o.value for o in purchase.outputs]
assert [o.script_pubkey.to_bytes() for o in purchase_variant.outputs]==[o.script_pubkey.to_bytes() for o in purchase.outputs]
commitment=h256(preimage(purchase,0,activation.outputs[0])[0])
assert commitment==h256(preimage(purchase_variant,0,activation.outputs[0])[0])
assert commitment==h256(preimage(listing_variant,0,activation.outputs[0])[0])
for candidate in (purchase_variant,listing_variant):
    for index,source in enumerate((activation.outputs[0],pf.outputs[0])):
        limits=InterpreterLimits(MinerPolicy(1048576,128,128*1024*1024,1000000,8),is_genesis_enabled=True,is_consensus=False)
        state=InterpreterState(limits,TxInputContext(candidate,index,source))
        state.evaluate_script(candidate.inputs[index].script_sig)
        state.evaluate_script(source.script_pubkey)
        assert state.stack[-1],('purchase-variant',index)
(HERE/'purchase-variant.json').write_text(json.dumps({
    'original':purchase.to_hex(),'variant':purchase_variant.to_hex(),
    'listingVariant':listing_variant.to_hex(),
    'commitment':commitment.hex(),'listingSource':activation.outputs[0].script_pubkey.to_bytes().hex(),
    'listingValue':activation.outputs[0].value,'fundingSource':pf.outputs[0].script_pubkey.to_bytes().hex(),
    'fundingValue':pf.outputs[0].value},indent=2)+'\n')

def push_spans(raw):
    spans=[];p=0
    while p<len(raw):
        start=p;opcode=raw[p];p+=1
        if opcode<=75: p+=opcode
        elif opcode==76: length=raw[p];p+=1+length
        elif opcode==77: length=int.from_bytes(raw[p:p+2],'little');p+=2+length
        elif opcode==78: length=int.from_bytes(raw[p:p+4],'little');p+=4+length
        elif opcode>96: raise ValueError('not a push-only unlocking script')
        assert p<=len(raw)
        spans.append(raw[start:p])
    return spans
purchase_pushes=push_spans(purchase.inputs[0].script_sig.to_bytes())
assert len(purchase_pushes)==15 and purchase_pushes[8]==b'\x00'
bad_units=b''.join(purchase_pushes[:8]+[b'\x51']+purchase_pushes[9:])
bad_extra=b'\x00'+purchase.inputs[0].script_sig.to_bytes()
negative_extra=[{
    'name':'purchase-unused-units-nonzero','transaction':purchase.to_hex(),
    'locking':activation.outputs[0].script_pubkey.to_bytes().hex(),
    'unlocking':bad_units.hex(),'value':1,'expected':False
},{
    'name':'purchase-extra-listing-push','transaction':purchase.to_hex(),
    'locking':activation.outputs[0].script_pubkey.to_bytes().hex(),
    'unlocking':bad_extra.hex(),'value':1,'expected':False,'preimageIndex':1
}]

split,sf=make_tx(purchase,0,[TxOutput(500,active),TxOutput(502,active),TxOutput(1,receipt(2,listing_id,n=2)),
    TxOutput(9990,change_script)],'split')
listing_unlock(split,purchase.outputs[0],2,units=500,admin=True,change_amount=9990)
funding_unlock(split,sf.outputs[0]);verify(split,[purchase.outputs[0],sf.outputs[0]],'split')

payout_items,payout_commit=payment_outputs(100)
payout,payfund=make_tx(split,0,[TxOutput(200,active),TxOutput(1,receipt(4,listing_id,300,1,payout_commit)),
    *payout_items,TxOutput(9990,change_script)],'payout')
listing_unlock(payout,split.outputs[0],4,units=100,change_amount=9990)
funding_unlock(payout,payfund.outputs[0]);verify(payout,[split.outputs[0],payfund.outputs[0]],'payout')

retire_items,retire_commit=payment_outputs(168)
retire,retfund=make_tx(split,1,[TxOutput(1,receipt(5,listing_id,504,0,retire_commit)),
    *retire_items,TxOutput(9990,change_script)],'retire',0xfffffffe,123456)
listing_unlock(retire,split.outputs[1],5,change_amount=9990)
funding_unlock(retire,retfund.outputs[0]);verify(retire,[split.outputs[1],retfund.outputs[0]],'retire')

for name,tx,source,position,replacement in [
    ('purchase-unused-admin-signature',purchase,activation.outputs[0],11,b'\x51'),
    ('split-unused-acquisition',split,purchase.outputs[0],3,b'\x20'+bytes([1])*32),
    ('payout-unused-admin-signature',payout,split.outputs[0],11,b'\x51'),
    ('retire-unused-units',retire,split.outputs[1],8,b'\x51'),
    ('activation-unused-proof-slot',activation,genesis.outputs[0],33,b'\x51'),
]:
    spans=push_spans(tx.inputs[0].script_sig.to_bytes())
    assert spans[position] in (b'\x00',b'\x20'+bytes(32)),name
    negative_extra.append({'name':name,'transaction':tx.to_hex(),
        'locking':source.script_pubkey.to_bytes().hex(),'unlocking':
        b''.join(spans[:position]+[replacement]+spans[position+1:]).hex(),
        'value':source.value,'expected':False,
        **({'preimageIndex':99} if name.startswith('activation') else {})})
# A second family listing at input one cannot pass the authenticated
# first-prevout/current-outpoint equality, even with genuine binder signatures.
dual=Tx(2,[TxInput(split.hash(),0,Script(),0xffffffff),
           TxInput(split.hash(),1,Script(),0xffffffff)],
        [TxOutput(1001,active),TxOutput(1,purchase_receipt)],0)
dual_pre,dual_prevouts,dual_z=preimage(dual,1,split.outputs[1])
dual_vals=[dual_pre,dual_prevouts,1,b'\x33'*32,b'\x44'*32,
           buyer.to_bytes(compressed=True),*buyer.to_point(),0,bytes(20),0,b'',
           dual_z,sig(2,dual_z,1),sig(3,dual_z,1)]
dual.inputs[1].script_sig=unlock(dual_vals)
negative_extra.append({'name':'second-listing-input-index-one',
    'transaction':dual.to_hex(),'locking':split.outputs[1].script_pubkey.to_bytes().hex(),
    'unlocking':dual.inputs[1].script_sig.to_bytes().hex(),
    'inputIndex':1,'value':split.outputs[1].value,'expected':False})
(HERE/'malleability-negative.json').write_text(json.dumps(negative_extra,indent=2)+'\n')

(HERE/'lineage-vectors.json').write_text(json.dumps(dict(
    genesis=genesis.to_hex(),funding=[x.to_hex() for x in (af,pf,sf,payfund,retfund)],
    records=records,roots=[x[0].to_bytes(compressed=True).hex() for x in (seller,r1,r2)],
    children=[x[1].to_bytes(compressed=True).hex() for x in (seller,r1,r2)]),indent=2)+'\n')

# Exercise all eight proof and payout slots with a completely signed funding path.
max_recipients=sorted((derive(d) for d in range(42,50)),
                      key=lambda item:item[0].to_bytes(compressed=True))
max_meta=bytearray(meta)
max_meta[156]=8
for i,recipient in enumerate(max_recipients):
    off=ENTRY+i*70
    max_meta[off:off+33]=recipient[0].to_bytes(compressed=True)
    max_meta[off+33:off+66]=recipient[1].to_bytes(compressed=True)
    max_meta[off+66:off+70]=u32(1)
max_stage=Script(push_item(max_meta)+b'\x75'+STAGE_PROGRAM)
max_active=Script(push_item(max_meta)+b'\x75'+ACTIVE_PROGRAM)
max_genesis=Tx(2,[TxInput(bytes([0xcc])*32,0,Script(),0xffffffff)],
               [TxOutput(1,max_stage)],0)
max_parent,max_af=make_tx(max_genesis,0,[TxOutput(1,max_active),
    TxOutput(9990,change_script)],'max8-activate')
listing_unlock(max_parent,max_genesis.outputs[0],0,change_amount=9990,
               proof_identities=[seller,*max_recipients])
funding_unlock(max_parent,max_af.outputs[0])
verify(max_parent,[max_genesis.outputs[0],max_af.outputs[0]],'max8-activate')
(HERE/'max8-activation.json.gz').write_bytes(gzip.compress(json.dumps({
    'locking':max_stage.to_bytes().hex(),
    'transaction':max_parent.to_hex(),
    'unlocking':max_parent.inputs[0].script_sig.to_bytes().hex(),
    'genesis':max_genesis.to_hex(),
    'funding':max_af.to_hex()
},separators=(',',':')).encode(),mtime=0))
assert max_meta[156]==8 and max_parent.outputs[0].value==1
max_purchase,max_pf=make_tx(max_parent,0,[TxOutput(1002,max_parent.outputs[0].script_pubkey),
    TxOutput(1,purchase_receipt),TxOutput(8990,change_script)],'max8-purchase')
listing_unlock(max_purchase,max_parent.outputs[0],1,change_amount=8990)
funding_unlock(max_purchase,max_pf.outputs[0])
verify(max_purchase,[max_parent.outputs[0],max_pf.outputs[0]],'max8-purchase')
max_items=[]
for i in range(8):
    off=ENTRY+i*70
    child_key=max_meta[off+33:off+66]
    weight=int.from_bytes(max_meta[off+66:off+70],'little')
    max_items.append(TxOutput(100*weight,p2pkh(child_key)))
max_wire=b''.join(u64(o.value)+b'\x19'+o.script_pubkey.to_bytes() for o in max_items)
max_payout,max_payfund=make_tx(max_purchase,0,[TxOutput(202,max_parent.outputs[0].script_pubkey),
    TxOutput(1,receipt(4,listing_id,800,1,hashlib.sha256(max_wire).digest())),
    *max_items,TxOutput(9990,change_script)],'max8-payout')
listing_unlock(max_payout,max_purchase.outputs[0],4,units=100,change_amount=9990)
funding_unlock(max_payout,max_payfund.outputs[0])
verify(max_payout,[max_purchase.outputs[0],max_payfund.outputs[0]],'max8-payout')
(HERE/'max8-active.json.gz').write_bytes(gzip.compress(json.dumps({
    'parent':max_parent.to_hex(),
    'funding':[max_pf.to_hex(),max_payfund.to_hex()],
    'purchase':max_purchase.to_hex(),
    'payout':max_payout.to_hex()
},separators=(',',':')).encode(),mtime=0))
