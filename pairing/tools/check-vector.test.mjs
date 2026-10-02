import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash,createHmac,hkdfSync} from 'node:crypto';

test('合成配对应用层向量在 Node 标准 crypto 中一致',()=>{
  const v=JSON.parse(readFileSync(new URL('../testdata/pairing-application-v1.json',import.meta.url),'utf8'));
  const c=v.context;
  const b64=(bytes)=>Buffer.from(bytes).toString('base64url');
  const json=(values)=>JSON.stringify(values);
  const context=json(['harmonia/pairing-context/v1','boringssl-spake2-edwards25519-draft02-v1',c.accountId,c.accountGeneration,c.purpose,c.sessionId,c.challengeNonce,c.expiresAt,c.initiatorDeviceId,c.initiatorSigningPublicKey,c.initiatorReceivingPublicKey,c.approverDeviceId,c.approverSigningPublicKey,c.approverReceivingPublicKey]);
  assert.equal(context,v.canonicalContext);
  assert.equal(json(['harmonia/pairing-identity/v1','initiator',b64(Buffer.from(context))]),v.initiatorIdentity);
  assert.equal(json(['harmonia/pairing-identity/v1','approver',b64(Buffer.from(context))]),v.approverIdentity);
  const amsg=Buffer.from(v.syntheticInitiatorMessageHex,'hex'),bmsg=Buffer.from(v.syntheticApproverMessageHex,'hex');
  const transcript=json(['harmonia/pairing-transcript/v1',b64(Buffer.from(context)),b64(amsg),b64(bmsg)]);
  assert.equal(transcript,v.transcript);
  const hash=createHash('sha256').update(transcript).digest();
  assert.equal(hash.toString('hex'),v.transcriptHashHex);
  const derive=(info)=>Buffer.from(hkdfSync('sha256',Buffer.from(v.syntheticRawKeyHex,'hex'),hash,info,32));
  for(const role of ['initiator','approver']){
    const mac=createHmac('sha256',derive(`harmonia/pairing-confirm/${role}/v1`)).update(json(['harmonia/pairing-confirmation/v1',role,b64(hash)])).digest('hex');
    assert.equal(mac,v[`${role}ConfirmationHex`]);
  }
  assert.equal(derive('harmonia/pairing-channel/v1').toString('hex'),v.channelKeyHex);
});
