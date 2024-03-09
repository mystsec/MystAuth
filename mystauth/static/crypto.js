//Check for passkey support, bioOnly indicates platform authenticator required for support to be true
async function checkSupport(bioOnly) {
  if (window.PublicKeyCredential) {
    if (!bioOnly)
    {
      return true;
    }
    else
    {
      let plat = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
      if (plat) {
        return true;
      }
      else {
        return false;
      }
    }
  }
  else {
    return false;
  }
}

/*
Convert  an ArrayBuffer into a string
from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
*/
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

/*
 Convert a string into an ArrayBuffer
 from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
 */
 function str2ab(str) {
   const buf = new ArrayBuffer(str.length);
   const bufView = new Uint8Array(buf);
   for (let i = 0, strLen = str.length; i < strLen; i++) {
     bufView[i] = str.charCodeAt(i);
   }
   return buf;
 }

 //https://stackoverflow.com/questions/9267899/arraybuffer-to-base64-encoded-string
 function ab2b64( buffer ) {
     var binary = '';
     var bytes = new Uint8Array( buffer );
     var len = bytes.byteLength;
     for (var i = 0; i < len; i++) {
         binary += String.fromCharCode( bytes[ i ] );
     }
     return window.btoa( binary );
 }

 //https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer
 function b642ab(base64) {
     var binaryString = atob(base64);
     var bytes = new Uint8Array(binaryString.length);
     for (var i = 0; i < binaryString.length; i++) {
         bytes[i] = binaryString.charCodeAt(i);
     }
     return bytes.buffer;
 }

 function encode_utf8(s) {
   return unescape(encodeURIComponent(s));
 }

 function decode_utf8(s) {
   return decodeURIComponent(escape(s));
 }

 function decodeU8A(arr) {
   return new TextDecoder().decode(arr);
 }

 function base64decode(str) {
   let decode = atob(str).replace(/[\x80-\uffff]/g, (m) => `%${m.charCodeAt(0).toString(16).padStart(2, '0')}`)
   return decodeURIComponent(decode)
 }

 function decodeBase64(s) {
     var e={},i,b=0,c,x,l=0,a,r='',w=String.fromCharCode,L=s.length;
     var A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
     for(i=0;i<64;i++){e[A.charAt(i)]=i;}
     for(x=0;x<L;x++){
         c=e[s.charAt(x)];b=(b<<6)+c;l+=6;
         while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(r+=w(a));}
     }
     return r;
 }

 function b64_to_b64url(s) {
   return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
 }

 function b64url_to_b64(s) {
   s = s.replace(/-/g, '+').replace(/_/g, '/');

   var pad = s.length % 4;
   if(pad) {
      if(pad === 1) {
          throw new Error('InvalidLengthError: Input string is the wrong length for base64 padding');
      }
      s += new Array(5-pad).join('=');
   }
   return s;
 }

function td2int(arr) {
  t = arr[1];
  d = arr[2];
  let tarr = t.split(':');
  let darr = d.split('-');
  let tint = parseInt(tarr[0]) * 3600 + parseInt(tarr[1]) * 60 + parseInt(tarr[2]);
  let dint = (parseInt(darr[0]) - 2020) * 365 + parseInt(darr[1]) * 30 + parseInt(darr[2]);
  return [dint, tint];
}

async function decodeFData(skey, fkey, edata)
{
  let fdata = await RSA_DECRYPT(skey, edata);

  fdata = fdata.split(":");
  let ciph = fdata[0];
  let iv = fdata[1];

  let key = await AES_DECRYPT(fkey, ciph, iv);
  return key;
}

async function AES_ENCRYPT(key, plaintext)
{
  return new Promise((resolve, reject) => {
    let iv = window.crypto.getRandomValues(new Uint8Array(128));
    window.crypto.subtle.importKey(
      "raw",
      str2ab(atob(b64url_to_b64(key))),
      'AES-GCM',
      false,
      ["encrypt"]
    ).then(async (key) => {
        await window.crypto.subtle.encrypt(
          {name: 'AES-GCM',
           iv: iv
          },
          key,
          str2ab(plaintext)
        ).then((ciphertext) => {
              iv = btoa(ab2str(iv));
              resolve([btoa(ab2str(ciphertext)), iv]);
            });
        });
  });
}

async function AES_DECRYPT(key, ciphertext, iv)
{
  return new Promise((resolve, reject) => {
    iv = str2ab(atob(b64url_to_b64(iv)));
    window.crypto.subtle.importKey(
      "raw",
      str2ab(atob(b64url_to_b64(key))),
      'AES-GCM',
      false,
      ["decrypt"]
    ).then(async (key) => {
        await window.crypto.subtle.decrypt(
          {name: 'AES-GCM',
           iv: iv
          },
          key,
          str2ab(atob(b64url_to_b64(ciphertext)))
        ).then((plaintext) => {
            resolve(ab2str(plaintext));
        });
    });
  });
}

async function generate_AES_KEY()
{
  let iterations = 1000000;
  let seed = window.crypto.getRandomValues(new Uint8Array(128));
  let salt = window.crypto.getRandomValues(new Uint8Array(64));

  return new Promise(async (resolve, reject) => {
    await window.crypto.subtle.importKey(
      'raw',
      seed,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    ).then(async (derivedKey) => {

        await window.crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt,
            iterations,
            hash: 'SHA-512',
          },
          derivedKey,
          {
            name: 'AES-GCM',
            length: 256,
          },
          true,
          ["encrypt", "decrypt"]
        ).then(async (keyMaterial) => {
          await window.crypto.subtle.exportKey(
            "raw",
            keyMaterial
          ).then(function(exportedSecretKey) {
            resolve([btoa(ab2str(exportedSecretKey)), btoa(ab2str(seed)), btoa(ab2str(salt))]);
          });
        });
      });
  });
}

async function derive_AES_KEY(sd, st)
{
  let seed = str2ab(atob(b64url_to_b64(sd)));
  let salt = str2ab(atob(b64url_to_b64(st)));
  let iterations = 1000000;

  return new Promise(async (resolve, reject) => {
    await window.crypto.subtle.importKey(
      'raw',
      seed,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    ).then(async (derivedKey) => {

        await window.crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt,
            iterations,
            hash: 'SHA-512',
          },
          derivedKey,
          {
            name: 'AES-GCM',
            length: 256,
          },
          true,
          ["encrypt", "decrypt"]
        ).then(async (keyMaterial) => {
          await window.crypto.subtle.exportKey(
            "raw",
            keyMaterial
          ).then(function(exportedSecretKey) {
            resolve(btoa(ab2str(exportedSecretKey)));
          });
        });
      });
  });
}

async function generate_RSA_KEY()
{
  return new Promise(async (resolve, reject) => {
    window.crypto.subtle.generateKey(
        {
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    ).then(async (key) => {
        await window.crypto.subtle.exportKey(
          "jwk",
          key.publicKey
        ).then(async function(exportedPublicKey) {
          let exportedPBKAsString = JSON.stringify(exportedPublicKey);
          let exportedPBKAsBase64 = b64_to_b64url(window.btoa(exportedPBKAsString));
            await window.crypto.subtle.exportKey(
              "pkcs8",
              key.privateKey
            ).then(async function(exportedPrivateKey) {
              const exportedPKAsString = ab2str(exportedPrivateKey);
              const exportedPKAsBase64 = b64_to_b64url(window.btoa(exportedPKAsString));
              resolve([exportedPBKAsBase64, exportedPKAsBase64]);
            });
        });
    });
  });
}

async function RSA_ENCRYPT(publicKey, message) {
  return new Promise((resolve, reject) => {
    let messageUint8Array = str2ab(message);
    window.crypto.subtle.importKey(
      "jwk",
      JSON.parse(window.atob(b64url_to_b64(publicKey))),
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      false,
      ["encrypt"]
    ).then(async (importedKey) => {
        await window.crypto.subtle.encrypt(
          {
            name: "RSA-OAEP",
          },
          importedKey,
          messageUint8Array
        ).then((ciphertext) => {
          resolve(btoa(ab2str(ciphertext)));
        });
    });
  });
}

async function RSA_DECRYPT(privateKey, ciphertext) {
  return new Promise((resolve, reject) => {
    let ciphertextUint8Array = str2ab(atob(b64url_to_b64(ciphertext)));
    window.crypto.subtle.importKey(
      "pkcs8",
      str2ab(window.atob(b64url_to_b64(privateKey))),
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      false,
      ["decrypt"]
    ).then(async (importedKey) => {
      await window.crypto.subtle.decrypt(
        {
          name: "RSA-OAEP",
        },
        importedKey,
        ciphertextUint8Array
      ).then((plaintext) => {
        resolve(ab2str(plaintext));
      });
    });
  });
}
