var form = document.getElementById("auth_form");
var csrftoken = document.querySelector("input[name='csrfmiddlewaretoken']").value;
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const rid = urlParams.get('rid');
const refLink = document.getElementById("ref").innerHTML;
var token = document.getElementById("token").innerHTML;
const eks = document.getElementById("eks").innerHTML == "True";
var nativeKeys = false;
var eKeys = "";
var fKeys = "";
var fData = "";

window.onload = async function() {
  if (! await checkSupport())
  {
    noPasskeySupport();
  }
  else if (! checkCookieSupport())
  {
    noCookieSupport();
  }
  console.log("%cStop!", "color: red; font-size: 3rem;");
  console.log("%cIf someone told you to paste anything here, they are scamming you and will compromise your secure account!", "font-size: 1.5rem;");
  console.log("%cDon't paste anything unless you fully understand what you are doing!", "font-size: 1.5rem;");
};

form.addEventListener('submit', async function(e) {
  e.preventDefault();
  let usr = document.getElementById("usr").value;
  loading();

  if (/^[a-zA-Z0-9_-]+$/.test(usr))
  {
    //Get Registration Options
    await fetch('/api/v1/user/reset/get/', {
        method: "POST",
        mode: "same-origin",
        credentials: "same-origin",
        headers: {'X-CSRFToken': csrftoken},
        body: JSON.stringify({'usr': usr, 'rid': rid, 'mc': token})
    }).then(response => response.json())
      .then(async (data) => {
        if (data[0] == 'failed')
        {
          document.getElementById("loading_msg").innerHTML = data[1];
        }
        else
        {
            //console.log(data);
            token = data[1];
            data = JSON.parse(data[0]);
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

              let bodyParams = {'resp': cred, 'uid': ab2str(data.user.id), 'rid': rid, 'mc': token, 'ref': refLink};

              if (urlParams.has("state"))
              {
                bodyParams.state = urlParams.get("state");
              }
              bodyParams.response_type = "myst";

              //Register Credential on Server
              await fetch('/api/v1/user/reset/verify/', {
                  method: "POST",
                  mode: "same-origin",
                  credentials: "same-origin",
                  headers: {'X-CSRFToken': csrftoken},
                  body: JSON.stringify(bodyParams)
              }).then(response => response.json())
                .then(async (data2) => {
                    //console.log(data2);
                    if (data2[0] == 'success')
                    {
                      document.getElementById("loading_msg").innerHTML = "Success, Redirecting . . .";
                      loading();

                      window.location.href = data2[1];
                    }
                    else
                    {
                      document.getElementById("loading_msg").innerHTML = data2[1];
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

});

function loading() {
  document.getElementById("auth_form_container").setAttribute("hidden", "none");
  document.getElementById("loading_container").removeAttribute("hidden");
}

function loaded() {
  document.getElementById("loading_container").setAttribute("hidden", "none");
  document.getElementById("auth_form_container").removeAttribute("hidden");
}
