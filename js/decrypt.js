String.prototype.decrypt = function(password) {
    const v = new Array(2);
    const k = new Array(4);
    let s = "";
    var i;

    for (var i = 0; i < 4; i++) k[i] = Str4ToLong(password.slice(i * 4, (i + 1) * 4));

    ciphertext = unescCtrlCh(this);
    for (i = 0; i < ciphertext.length; i += 8) { // decode ciphertext into s in 64-bit (8 char) blocks
    v[0] = Str4ToLong(ciphertext.slice(i, i + 4));
    v[1] = Str4ToLong(ciphertext.slice(i + 4, i + 8));
    decode(v, k);
    s += LongToStr4(v[0]) + LongToStr4(v[1]);
  }

    // strip trailing null chars resulting from filling 4-char blocks:
    s = s.replace(/\0+$/, '');

    return unescape(s);
};
// Like C code

function decode(v, k) {
    let y = v[0];
    let z = v[1];
    const delta = 0x9E3779B9;
    let sum = delta * 32;

    while (sum != 0) {
    z -= (y << 4 ^ y >>> 5) + y ^ sum + k[sum >>> 11 & 3];
    sum -= delta;
    y -= (z << 4 ^ z >>> 5) + z ^ sum + k[sum & 3];
  }
    v[0] = y;
    v[1] = z;
}


// supporting functions

function Str4ToLong(s) { // convert 4 chars of s to a numeric long
  let v = 0;
  for (let i = 0; i < 4; i++) v |= s.charCodeAt(i) << i * 8;
  return isNaN(v) ? 0 : v;
}

function LongToStr4(v) { // convert a numeric long to 4 char string
  const s = String.fromCharCode(v & 0xFF, v >> 8 & 0xFF, v >> 16 & 0xFF, v >> 24 & 0xFF);
  return s;
}

function escCtrlCh(str) { // escape control chars which might cause problems with encrypted texts
  return str.replace(/[\0\t\n\v\f\r\xa0'"!]/g, c => `!${c.charCodeAt(0)}!`);
}

function unescCtrlCh(str) { // unescape potentially problematic nulls and control characters
  return str.replace(/!\d\d?\d?!/g, c => String.fromCharCode(c.slice(1, -1)));
}