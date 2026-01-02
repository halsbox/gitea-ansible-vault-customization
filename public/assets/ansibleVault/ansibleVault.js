"use strict";
var ansibleVault = function(data) {
  let header = data.match(/^\$ANSIBLE_VAULT;1\.[12];AES256(?:;[^\s]+)?\s+/),
      h2b = sjcl.codec.hex.toBits,
      b2h = sjcl.codec.hex.fromBits,
      u2b = sjcl.codec.utf8String.toBits,
      b2u = sjcl.codec.utf8String.fromBits,
      bSlice = sjcl.bitArray.bitSlice,
      bEq = sjcl.bitArray.equal,
      hmac = sjcl.misc.hmac,
      sha256 = sjcl.hash.sha256,
      aes = sjcl.cipher.aes,
      dCTR = sjcl.mode.ctr.decrypt,
      eCTR = sjcl.mode.ctr.encrypt,
      pbkdf2 = (p,s) => sjcl.misc.pbkdf2(p, s, 10000, 640),
      key1 = k => bSlice(k, 0, 256),
      key2 = k => bSlice(k, 256, 512),
      iv = k => bSlice(k, 512, 640),
      unwrap = w => w.replace(/[^0-9a-fA-F]+/m,''),
      wrap = u => u.split('').map((c,i) => i>0?(i%80?c:'\n'+c):c).join(''),
      unpad = t => t.substr(0,t.length-t.charCodeAt(t.length-1)),
      pad = t => {const p=32-(new TextEncoder().encode(t)).length%32;return t+String.fromCharCode(p).repeat(p);},
      uSplit = h => b2u(h2b(unwrap(h))).split('\n').map(s => h2b(s)),
      bJoin = (s,h,b) => wrap(b2h(u2b([s,h,b].map(j => b2h(j)).join('\n'))));
  this.isValid = function() {return !!this._cData;}
  this.decrypt = function(password) {
    const dKey = pbkdf2(password, this._salt);
    this._iv = iv(dKey);
    this._hmac = new hmac(key2(dKey), sha256);
    if (!bEq(this._hmac.encrypt(this._cData), this._cHmac)) return null;
    this._aes = new aes(key1(dKey));
    return unpad(b2u(dCTR(this._aes, this._cData, this._iv)));
  }
  this.encrypt = function(text) {
    let cData = eCTR(this._aes, u2b(pad(text)), this._iv);
    return this._header + bJoin(this._salt, this._hmac.encrypt(cData), cData);
  }
  if (header) {
    this._header = header[0];
    try {[this._salt, this._cHmac, this._cData] = uSplit(data.substr(this._header.length));}catch (e) { }
  }
};
