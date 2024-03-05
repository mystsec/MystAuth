var form = document.getElementById("auth_form");
var csrftoken = document.querySelector("input[name='csrfmiddlewaretoken']").value;
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const rid = document.getElementById("rid").innerHTML;
const refLink = document.getElementById("ref").innerHTML;
const rstLink = prepURL(document.getElementById("reset").innerHTML);
const bioOnly = document.getElementById("bioOnly").innerHTML == "True";
const eks = document.getElementById("eks").innerHTML == "True";
var eksF = document.getElementById("eksF").innerHTML == "True";
const isPopup = document.getElementById("display").innerHTML == "popup";
var lastUsr = document.getElementById("usr").value;
var isLoading = false;
var nativeKeys = false;
var eKeys = "";
var fKeys = "";
var fData = "";
var eData = "";

window.onload = async function() {
  document.getElementById("usr").value = "";
  if (window.location.hash == "#login")
  {
    select("signin");
  }
  if (! await checkSupport(bioOnly))
  {
    noPasskeySupport();
  }
  else if (! checkCookieSupport())
  {
    noCookieSupport();
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
  if (usr.length > 255)
  {
    notify("Username must be less than 255 characters!", 0);
  }
  else if (!onlySpaces(usr) && t1) {
    loading();

    if (/^[a-zA-Z0-9_-]+$/.test(usr))
    {
      //Get Registration Options
      await fetch('/api/v1/user/register/get/', {
          method: "POST",
          mode: "same-origin",
          credentials: "same-origin",
          headers: {'X-CSRFToken': csrftoken},
          body: JSON.stringify({'usr': usr, 'rid': rid, 'eks': eks})
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
              var uid = decodeBase64(data.user.id);
              data.user.id = str2ab(uid);
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

                if (eks)
                {
                  document.getElementById("loading_msg").innerHTML = "Securing Encryption Keys ...";
                  let extResults = credential.getClientExtensionResults();

                  var keyData = await generate_AES_KEY();
                  var secretStr = keyData[1] + ":" + keyData[2];
                  let ek = await RSA_ENCRYPT(urlParams.get('pbk'), keyData[0]);
                  eKeys = b64_to_b64url(ek);

                  if (eksF)
                  {
                    var fKeyData = await generate_AES_KEY();
                    let fk = await RSA_ENCRYPT(urlParams.get('pbk'), fKeyData[0]);
                    fKeys = b64_to_b64url(fk);
                    let fd = await AES_ENCRYPT(fKeyData[0], keyData[0]);
                    fData = b64_to_b64url(fd[0]) + ":" + b64_to_b64url(fd[1]);
                  }

                  if (typeof extResults.largeBlob !== "undefined" && (extResults.largeBlob || extResults.largeBlob.supported))
                  {
                    document.getElementById("loading_msg").innerHTML = "Verify One More Time ...";

                    let publicKeyCredentialRequestOptions = {
                      challenge: data.challenge,
                      rpId: "localhost",
                      timeout: 60000,
                      allowCredentials: [{
                        type: "public-key",
                        id: credential.rawId,
                      }],
                      extensions: {
                        largeBlob: {
                          write: Uint8Array.from(secretStr.split("").map(c => c.codePointAt(0))),
                        },
                      },
                    };
                    navigator.credentials.get({
                        publicKey: publicKeyCredentialRequestOptions
                    }).then(async (assertion) => {
                      nativeKeys = assertion.getClientExtensionResults().largeBlob.written;
                      registerUser(cred, data);
                    });
                  }
                  else
                  {
                    registerUser(cred, data);
                  }
                }
                else
                {
                  registerUser(cred, data);
                }
              }
              catch (e) {
                await fetch('/api/v1/user/register/drop/', {
                  method: "POST",
                  mode: "same-origin",
                  credentials: "same-origin",
                  headers: {'X-CSRFToken': csrftoken},
                  body: JSON.stringify({'usr': usr, 'rid': rid, 'uid': uid})
                });
                loaded();
                notify("Cancelled or Failed!", 0);
                console.log(e.stack);
                console.log(e.name);
                console.log(e.message);
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
        body: JSON.stringify({'usr': usr, 'rid': rid, 'eks': eks})
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
            if (eks)
            {
              fData = data.fdata;
              if (fData == null)
              {
                eksF = false;
              }
              else
              {
                eksF = true;
              }
              delete data['fdata']
            }
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

              if (eks)
              {
                document.getElementById("loading_msg").innerHTML = "Securing Encryption Keys ...";
                if (typeof assertion.getClientExtensionResults().largeBlob == "undefined" || typeof assertion.getClientExtensionResults().largeBlob.blob == "undefined")
                {
                  if (eksF)
                  {
                    let ed = await RSA_ENCRYPT(urlParams.get('pbk'), fData);
                    eData = b64_to_b64url(ed);
                  }
                }
                else
                {
                  nativeKeys = true;
                  let secretStr = String.fromCodePoint(...new Uint8Array(assertion.getClientExtensionResults().largeBlob.blob));
                  secretStr = secretStr.split(":");
                  var seed = secretStr[0];
                  var salt = secretStr[1];
                  var key = await derive_AES_KEY(seed, salt);
                  let ek = await RSA_ENCRYPT(urlParams.get('pbk'), key);
                  eKeys = b64_to_b64url(ek);
                }
                authenticateUser(cred, usr);
              }
              else
              {
                authenticateUser(cred, usr);
              }
            }
            catch (e) {
              loaded();
              notify("Cancelled or Failed!", 0);
              console.log(e.stack);
              console.log(e.name);
              console.log(e.message);
            }
        }
      });
  }
  else
  {
    notify("Please Enter a Username", 0);
  }
});

async function registerUser(cred, data)
{
  var bodyParams = {'resp': cred, 'uid': ab2str(data.user.id), 'rid': rid, 'ref': refLink};

  if (eks)
  {
    if (nativeKeys || eksF)
    {
      bodyParams.ekeys = eKeys;
    }
    else
    {
      bodyParams.eksUnavailable = "True";
    }

    if (eksF)
    {
      bodyParams.fkeys = fKeys;
      bodyParams.fdata = fData;
    }
    bodyParams.nativekeys = nativeKeys;
  }

  if (urlParams.has("state"))
  {
    bodyParams.state = urlParams.get("state");
  }

  if (window.location.pathname == "/authorize/")
  {
    bodyParams.nonce = urlParams.get("nonce");
    bodyParams.response_type = urlParams.get("response_type");
    bodyParams.scope = urlParams.get("scope");
  }
  else
  {
    bodyParams.response_type = "myst";
  }

  console.log(bodyParams);

  //Register Credential on Server
  await fetch('/api/v1/user/register/verify/', {
      method: "POST",
      mode: "same-origin",
      credentials: "same-origin",
      headers: {'X-CSRFToken': csrftoken},
      body: JSON.stringify(bodyParams)
  }).then(response => response.json())
    .then(async (data2) => {
        //console.log(data2);
        loaded();
        if (data2[0] == 'success')
        {
          document.getElementById("usr").value = '';
          document.getElementById("loading_msg").innerHTML = "Account Created, Redirecting . . .";
          loading();

          window.location.href = data2[1];
        }
        else
        {
          notify(data2[1], 0);
        }
    });
}

async function authenticateUser(cred, usr)
{
  var bodyParams = {'resp': cred, 'usr': usr, 'rid': rid, 'ref': refLink};

  if (eks)
  {
    if (eKeys != "")
    {
      bodyParams.ekeys = eKeys;
    }
    else if (eData != "")
    {
      bodyParams.edata = eData;
    }
    else
    {
      bodyParams.eksUnavailable = "True";
    }
  }

  if (urlParams.has("state"))
  {
    bodyParams.state = urlParams.get("state");
  }

  if (window.location.pathname == "/authorize/")
  {
    bodyParams.nonce = urlParams.get("nonce");
    bodyParams.response_type = urlParams.get("response_type");
    bodyParams.scope = urlParams.get("scope");
  }
  else
  {
    bodyParams.response_type = "myst";
  }

  //Authenticate with Server
  await fetch('/api/v1/user/authenticate/verify/', {
      method: "POST",
      mode: "same-origin",
      credentials: "same-origin",
      headers: {'X-CSRFToken': csrftoken},
      body: JSON.stringify(bodyParams)
  }).then(response => response.json())
    .then(async (data2) => {
        //console.log(data2);
        loaded();
        if (data2[0] == 'success')
        {
          document.getElementById("usr").value = '';
          document.getElementById("loading_msg").innerHTML = "Success, Redirecting . . .";
          loading();

          window.location.href = data2[1];
        }
        else
        {
          notify(data2[1], 0);
        }
    });
}

async function select(id) {
  if (!isLoading)
  {
    let support = await checkSupport(bioOnly);
    let reset = document.getElementById("reset").innerHTML.length > 0;
    let resetCont = document.getElementById("reset_container");

    var elements = document.querySelectorAll('[name="selection"]');
    elements.forEach(function(element) {
      element.setAttribute("aria-selected", "false");
    });
    document.getElementById(id).setAttribute("aria-selected", "true");
    document.getElementById('notif').innerHTML = '';

    if (support)
    {
      if (checkCookieSupport())
      {
        if (id === "signup") {
          resetCont.setAttribute("hidden", "none");
          document.getElementById("submit").innerHTML = "Create Account";
          document.getElementById("loading_msg").innerHTML = "Use Device to Create . . .";
          lastUsr = document.getElementById("usr").value;
          document.getElementById("usr").value = '';
        }
        else {
          document.getElementById("usr").value = lastUsr;
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
        noCookieSupport();
      }
    }
    else
    {
      noPasskeySupport();
    }
  }
}

function loading()
{
  document.getElementById("auth_form_container").setAttribute("hidden", "none");
  document.getElementById("reset_container").setAttribute("hidden", "none")
  document.getElementById("loading_container").removeAttribute("hidden");
  isLoading = true;
}

function loaded()
{
  document.getElementById("loading_container").setAttribute("hidden", "none");
  document.getElementById("auth_form_container").removeAttribute("hidden");
  let reset = document.getElementById("reset").innerHTML.length > 0;
  let resetCont = document.getElementById("reset_container");
  if (reset)
  {
    resetCont.removeAttribute("hidden");
  }
  isLoading = false;
}
