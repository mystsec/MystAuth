var form = document.getElementById("auth_form");
var csrftoken = document.querySelector("input[name='csrfmiddlewaretoken']").value;
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const rid = urlParams.get('rid');
const refLink = document.getElementById("ref").innerHTML;
const rstLink = prepURL(document.getElementById("reset").innerHTML);

window.onload = async function() {
  if (window.location.hash == "#login")
  {
    select("signin");
  }
  if (! await checkSupport())
  {
    document.getElementById("loading_msg").innerHTML = "Your Device/Browser Doesn't Support <a href='https://blog.google/inside-google/googlers/ask-a-techspert/how-passkeys-work/' target='_blank'>Passkeys</a> 😢 <br><br><a href='https://passkeys.dev/device-support/#matrix' target='_blank'>Check Support</a>";
    loading();
  }
  console.log("%cStop!", "color: red; font-size: 3rem;");
  console.log("%cIf someone told you to paste anything here, they are scamming you and will compromise your secure account!", "font-size: 1.5rem;");
  console.log("%cDon't paste anything unless you understand what you are doing completely!", "font-size: 1.5rem;");
};

form.addEventListener('submit', async function(e) {
  e.preventDefault();
  let usr = document.getElementById("usr").value;
  let t1 = document.getElementById("signup").getAttribute("aria-selected") === 'true';
  let t2 = document.getElementById("signin").getAttribute("aria-selected") === 'true';
  if (!onlySpaces(usr) && t1) {
    loading();

    if (/^[a-zA-Z0-9_-]+$/.test(usr))
    {
      //Get Registration Options
      await fetch('/api/v1/user/register/get/', {
          method: "POST",
          mode: "same-origin",
          credentials: "same-origin",
          headers: {'X-CSRFToken': csrftoken},
          body: JSON.stringify({'usr': usr, 'rid': rid})
      }).then(response => response.json())
        .then(async (data) => {
          //console.log(data);
          if (data[0] == 'failed')
          {
            loaded();
            notify(data[1], 0);
          }
          else
          {
              data = JSON.parse(data);
              data.user.id = str2ab(decodeBase64(data.user.id));
              data.challenge = str2ab(decodeBase64(data.challenge));
              let publicKeyCredentialCreationOptions = data;
              //console.log(publicKeyCredentialCreationOptions);

              //Create New Credential
              try {
                const credential = await navigator.credentials.create({
                    publicKey: publicKeyCredentialCreationOptions
                });

                //console.log(credential);

                cred = {};
                cred.authenticatorAttachment = credential.authenticatorAttachment;
                cred.id = credential.id;
                cred.rawId = ab2b64(credential.rawId);
                cred.response = {
                  "attestationObject": ab2b64(credential.response.attestationObject),
                  "clientDataJSON": ab2b64(credential.response.clientDataJSON),
                  "authenticatorData": ab2b64(credential.response.getAuthenticatorData()),
                  "publicKey": ab2b64(credential.response.getPublicKey()),
                  "publicKeyAlgorithm": credential.response.getPublicKeyAlgorithm(),
                  "transports": credential.response.getTransports()
                };
                cred.type = credential.type;

                //console.log(cred);
                //console.log(JSON.stringify(credential));

                //Register Credential on Server
                await fetch('/api/v1/user/register/verify/', {
                    method: "POST",
                    mode: "same-origin",
                    credentials: "same-origin",
                    headers: {'X-CSRFToken': csrftoken},
                    body: JSON.stringify({'resp': cred, 'uid': ab2str(data.user.id), 'rid': rid})
                }).then(response => response.json())
                  .then(async (data2) => {
                      //console.log(data2);
                      loaded();
                      if (data2[0] == 'success')
                      {
                        document.getElementById("usr").value = '';
                        //notify('Account Created, Redirecting . . .', 1);
                        document.getElementById("loading_msg").innerHTML = "Account Created, Redirecting . . .";
                        loading();

                        if (urlParams.has('ref'))
                        {
                          let ref = prepURL(refLink);
                          if (ref.includes("?"))
                          {
                            ref = ref + "&usr="+usr+"&token="+data2[1];
                          }
                          else
                          {
                            ref = ref + "?usr="+usr+"&token="+data2[1];
                          }
                          window.location.href = ref;
                        }
                        else
                        {
                          data2 = '';
                          notify("Failed!", 0);
                        }
                      }
                      else
                      {
                        notify(data2[1], 0);
                      }
                  });
              }
              catch {
                loaded();
                notify("Cancelled or Failed!", 0);
              }

          }
        });
    }
    else
    {
      loaded();
      notify("Only Alphanumerics, Underscore, and Hyphen Allowed in Username", 0);
    }
  }
  else if(!onlySpaces(usr))
  {
    loading();

    //Get Authentication Options
    await fetch('/api/v1/user/authenticate/get/', {
        method: "POST",
        mode: "same-origin",
        credentials: "same-origin",
        headers: {'X-CSRFToken': csrftoken},
        body: JSON.stringify({'usr': usr, 'rid': rid})
    }).then(response => response.json())
      .then(async (data) => {
        //console.log(data);
        if (data[0] == 'failed')
        {
          loaded();
          notify(data[1], 0);
        }
        else
        {
            data = JSON.parse(data);
            data.allowCredentials[0].id = str2ab(decodeBase64(data.allowCredentials[0].id));
            data.challenge = str2ab(decodeBase64(data.challenge));
            let publicKeyCredentialRequestOptions = data;
            //console.log(publicKeyCredentialRequestOptions);

            //Get Assertion
            try {
              const assertion = await navigator.credentials.get({
                  publicKey: publicKeyCredentialRequestOptions
              });

              //console.log(assertion);

              cred = {};
              cred.authenticatorAttachment = assertion.authenticatorAttachment;
              cred.id = assertion.id;
              cred.rawId = ab2b64(assertion.rawId);
              cred.response = {
                "clientDataJSON": ab2b64(assertion.response.clientDataJSON),
                "authenticatorData": ab2b64(assertion.response.authenticatorData),
                "signature": ab2b64(assertion.response.signature),
                "userHandle": ab2b64(assertion.response.userHandle),
              };
              cred.type = assertion.type;

              //console.log(cred);
              //console.log(JSON.stringify(credential));

              //Authenticate with Server
              await fetch('/api/v1/user/authenticate/verify/', {
                  method: "POST",
                  mode: "same-origin",
                  credentials: "same-origin",
                  headers: {'X-CSRFToken': csrftoken},
                  body: JSON.stringify({'resp': cred, 'usr': usr, 'rid': rid})
              }).then(response => response.json())
                .then(async (data2) => {
                    console.log(data2);
                    loaded();
                    if (data2[0] == 'success')
                    {
                      document.getElementById("usr").value = '';
                      //notify('Authenticated, Redirecting . . .', 1);
                      document.getElementById("loading_msg").innerHTML = "Success, Redirecting . . .";
                      loading();

                      if (urlParams.has('ref'))
                      {
                        let ref = prepURL(refLink);
                        if (ref.includes("?"))
                        {
                          ref = ref + "&usr="+usr+"&token="+data2[1];
                        }
                        else
                        {
                          ref = ref + "?usr="+usr+"&token="+data2[1];
                        }
                        window.location.href = ref;
                      }
                      else
                      {
                        data2 = '';
                        notify("Failed!", 0);
                      }
                    }
                    else
                    {
                      notify(data2[1], 0);
                    }
                });
            }
            catch {
              loaded();
              notify("Cancelled or Failed!", 0);
            }
        }
      });
  }
  else
  {
    notify("Please Enter a Username", 0);
  }
});

async function select(id) {
  let support = await checkSupport();
  let reset = document.getElementById("reset").innerHTML.length > 0;
  let resetCont = document.getElementById("reset_container");
  if (support)
  {
    var elements = document.querySelectorAll('[name="selection"]');
    elements.forEach(function(element) {
      element.setAttribute("aria-selected", "false");
    });
    document.getElementById(id).setAttribute("aria-selected", "true");
    document.getElementById('notif').innerHTML = '';
    if (id === "signup") {
      resetCont.setAttribute("hidden", "none");
      document.getElementById("submit").innerHTML = "Create Account";
      document.getElementById("loading_msg").innerHTML = "Use Device to Create . . .";
      //document.getElementById("loading_msg").innerHTML = "Use USB Security Key . . .";
    }
    else {
      document.getElementById("submit").innerHTML = "Log In with Passkey";
      document.getElementById("loading_msg").innerHTML = "Authenticate Using Device . . .";
      if (reset)
      {
        document.getElementById("reset_link").setAttribute("href", rstLink);
        resetCont.removeAttribute("hidden");
      }
    }
  }
  else
  {
    var elements = document.querySelectorAll('[name="selection"]');
    elements.forEach(function(element) {
      element.setAttribute("aria-selected", "false");
    });
    document.getElementById(id).setAttribute("aria-selected", "true");
    document.getElementById('notif').innerHTML = '';
    document.getElementById("loading_msg").innerHTML = "Your Device/Browser Doesn't Support <a href='https://blog.google/inside-google/googlers/ask-a-techspert/how-passkeys>
    loading();
  }
}

async function checkSupport() {
  let bioOnly = document.getElementById("bioOnly").innerHTML == "True";
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

function notify(str, type) {
  let notif = document.getElementById('notif');
  if (type == 0)
  {
    notif.setAttribute('success', 'false');
  }
  else
  {
    notif.setAttribute('success', 'true');
  }
  notif.innerHTML = str;
}

function loading() {
  document.getElementById("auth_form_container").setAttribute("hidden", "none");
  document.getElementById("loading_container").removeAttribute("hidden");
}

function loaded() {
  document.getElementById("loading_container").setAttribute("hidden", "none");
  document.getElementById("auth_form_container").removeAttribute("hidden");
}

function onlySpaces(str)
{
  return str.replace(/\s/g, '').length == 0;
}

function prepURL(url)
{
  url = decodeURIComponent(url);
  return url.replace(/"/g, "%22").replace(/'/g, "%27").replace(/</g, "%3C").replace(/>/g, "%3E");
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
   return s.replace(/\+/g, '-').replace(/\//g, '_');
 }

 function b64url_to_b64(s) {
   return s.replace(/-/g, '+').replace(/_/g, '/');
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

function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

async function AES_ENCRYPT(key, plaintext)
{
  return new Promise((resolve, reject) => {
    let iv = window.crypto.getRandomValues(new Uint8Array(128));
    window.crypto.subtle.importKey(
      "raw",
      str2ab(atob(key)),
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
    iv = str2ab(atob(iv));
    window.crypto.subtle.importKey(
      "raw",
      str2ab(atob(key)),
      'AES-GCM',
      false,
      ["decrypt"]
    ).then(async (key) => {
        await window.crypto.subtle.decrypt(
          {name: 'AES-GCM',
           iv: iv
          },
          key,
          str2ab(atob(ciphertext))
        ).then((plaintext) => {
            resolve(ab2str(plaintext));
        });
    });
  });
}

async function generate_AES_KEY()
{
  const iterations = 1000000;

  return new Promise(async (resolve, reject) => {
  const seed = window.crypto.getRandomValues(new Uint8Array(64));
  const salt = window.crypto.getRandomValues(new Uint8Array(64));
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
          const exportedAsString = ab2str(exportedSecretKey);
          const exportedAsBase64 = window.btoa(exportedAsString);
          resolve([exportedAsBase64, btoa(ab2str(seed)), btoa(ab2str(salt))]);

        });
      });
    });
  });
}

async function generate_AES_KEY(sd, st)
{
  const seed = str2ab(atob(b64url_to_b64(sd)));
  const salt = str2ab(atob(b64url_to_b64(st)));
  const iterations = 1000000;

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
          const exportedAsString = ab2str(exportedSecretKey);
          const exportedAsBase64 = window.btoa(exportedAsString);
          resolve(exportedAsBase64);

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
          let exportedPBKAsBase64 = exportedPBKAsString;
            await window.crypto.subtle.exportKey(
              "pkcs8",
              key.privateKey
            ).then(async function(exportedPrivateKey) {
              const exportedPKAsString = ab2str(exportedPrivateKey);
              const exportedPKAsBase64 = window.btoa(exportedPKAsString);
              resolve([exportedPBKAsBase64, exportedPKAsBase64]);
            });
        });
    });
  });
}
