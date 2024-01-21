var editForm = document.getElementById("edit-form");
var cycForm = document.getElementById("key-form");
var delForm = document.getElementById("del-form");
var csrftoken = document.querySelector("input[name='csrfmiddlewaretoken']").value;
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);

document.getElementById('hnm').onclick = function() {
  window.open('/');
};

window.onload = function() {
  urlParams.set("token", document.getElementById("token").innerHTML);
  let url = window.location.pathname + '?' + urlParams.toString() + window.location.hash;
  window.history.replaceState({}, "",  url);
};

editForm.addEventListener('submit', async function(e) {
  e.preventDefault();
  let usr = document.getElementById("usr").innerHTML;
  let token = document.getElementById("token").innerHTML;
  let id = document.getElementById("id").innerHTML;
  let apiKey = document.getElementById("key").value;
  let oid = document.getElementById("oid").value;
  let ttl = document.getElementById("ttl").value;
  let bioOnly = document.getElementById("bioOnly").value;
  let allowReset = document.getElementById("allowReset").value;

  if (!onlySpaces(oid) && !onlySpaces(ttl) && !onlySpaces(bioOnly) && !onlySpaces(apiKey))
  {
    ttl = +ttl;
    notify("Updating . . .", 2, 'edit');
    await fetch('/api/v1/origin/edit/', {
        method: "POST",
        mode: "same-origin",
        credentials: "same-origin",
        headers: {'X-CSRFToken': csrftoken},
        body: JSON.stringify({'oid': oid, 'usr': usr, 'token': token, 'id': id, 'apiKey': apiKey, 'ttl': ttl, 'bioOnly': bioOnly, 'allowReset': allowReset})
    }).then(response => response.json())
      .then(async (data) => {
        if (data['success'])
        {
          notify('Success!', 1, 'edit');
          document.getElementById("oid").value = data['oid'];
          document.getElementById("ttl").value = data['ttl'];
          document.getElementById("bioOnly").value = data['bioOnly'];
          document.getElementById("allowReset").value = data['allowReset'];
          document.getElementById("key").value = "";
          setToken(data["token"]);
        }
        else
        {
          notify(data['info'], 0, 'edit');
          if (data["token"] != undefined) {
            setToken(data["token"]);
          }
          else
          {
            console.log("Auth Failed");
          }
          if (data['info'].includes("Time"))
          {
            window.location.href = "/auth/?rid=0e3b8c98b34e43a5885e41061d15bce2&img=RdELgb1bNz8&usr="+usr+"&ref=https://mystauth.com/dash#login";
          }
        }
      });
  }
});

cycForm.addEventListener('submit', async function(e) {
  e.preventDefault();
  let usr = document.getElementById("usr").innerHTML;
  let token = document.getElementById("token").innerHTML;
  let id = document.getElementById("id").innerHTML;
  let apiKey = document.getElementById("old-key").value;

  if (!onlySpaces(apiKey))
  {
    notify("Cycling . . .", 2, 'cyc');
    await fetch('/api/v1/origin/cycle/', {
        method: "POST",
        mode: "same-origin",
        credentials: "same-origin",
        headers: {'X-CSRFToken': csrftoken},
        body: JSON.stringify({'usr': usr, 'token': token, 'id': id, 'apiKey': apiKey})
    }).then(response => response.json())
      .then(async (data) => {
        if (data['success'])
        {
          notify('Success!', 1, 'cyc');
          document.getElementById("old-key").value = "";
          document.getElementById("new-key").innerHTML = data['apiKey'];
          document.getElementById("new-creds").removeAttribute("hidden");
          setToken(data["token"]);
        }
        else
        {
          notify(data['info'], 0, 'cyc');
          if (data["token"] != undefined) {
            setToken(data["token"]);
          }
          else
          {
            console.log("Auth Failed");
          }
          if (data['info'].includes("Time"))
          {
            window.location.href = "/auth/?rid=0e3b8c98b34e43a5885e41061d15bce2&img=RdELgb1bNz8&usr="+usr+"&ref=https://mystauth.com/dash#login";
          }
        }
      });
  }
});


delForm.addEventListener('submit', async function(e) {
  e.preventDefault();
  let usr = document.getElementById("usr").innerHTML;
  let token = document.getElementById("token").innerHTML;
  let id = document.getElementById("id").innerHTML;
  let apiKey = document.getElementById("del-key").value;

  if (!onlySpaces(apiKey))
  {
    notify("Deleting . . .", 2, 'del');
    await fetch('/api/v1/origin/delete/', {
        method: "POST",
        mode: "same-origin",
        credentials: "same-origin",
        headers: {'X-CSRFToken': csrftoken},
        body: JSON.stringify({'usr': usr, 'token': token, 'id': id, 'apiKey': apiKey})
    }).then(response => response.json())
      .then(async (data) => {
        if (data['success'])
        {
          notify('Success!', 1, 'del');
          document.getElementById("del-key").value = "";
          setToken(data["token"]);
          window.location.reload();
        }
        else
        {
          notify(data['info'], 0, 'del');
          if (data["token"] != undefined) {
            setToken(data["token"]);
          }
          else
          {
            console.log("Auth Failed");
          }
          if (data['info'].includes("Time"))
          {
            window.location.href = "/auth/?rid=0e3b8c98b34e43a5885e41061d15bce2&img=RdELgb1bNz8&usr="+usr+"&ref=https://mystauth.com/dash#login";
          }
        }
      });
  }
});


function onlySpaces(str)
{
  return str.replace(/\s/g, '').length == 0;
}

function setToken(token)
{
  document.getElementById("token").innerHTML = token;
  urlParams.set("token", token);
  let url = window.location.pathname + '?' + urlParams.toString() + window.location.hash;
  window.history.replaceState({}, "",  url);
}

function notify(str, type, form) {
  let notif = document.getElementById(form+'-notif');
  if (type == 0)
  {
    notif.setAttribute('success', 'false');
  }
  else if (type == 1)
  {
    notif.setAttribute('success', 'true');
  }
  else
  {
    notif.removeAttribute('success');
  }
  notif.innerHTML = str;
}
