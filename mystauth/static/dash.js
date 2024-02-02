var form = document.getElementById("reg-form");
var csrftoken = document.querySelector("input[name='csrfmiddlewaretoken']").value;
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);

document.getElementById('hnm').onclick = function() {
  window.open('/');
};

window.onload = function() {
  urlParams.delete('usr');
  urlParams.delete('token');
  urlParams.delete('state');
  let url = window.location.pathname + '?' + urlParams.toString() + window.location.hash;
  window.history.replaceState({}, "",  url);
};

document.getElementById("signout").onclick = async function() {
  await fetch('/dash/signout/', {
    method: "POST",
    mode: "same-origin",
    credentials: "same-origin",
    headers: {'X-CSRFToken': csrftoken}
  }).then(response => {
    window.location.href = "/dash";
  });
}

form.addEventListener('submit', async function(e) {
  e.preventDefault();
  let usr = document.getElementById("usr").innerHTML;
  let nOid = document.getElementById("oid").value;

  if (!onlySpaces(nOid))
  {
    notify('Creating Account . . .', 2);
    await fetch('/api/v1/origin/new/', {
        method: "POST",
        mode: "same-origin",
        credentials: "same-origin",
        headers: {'X-CSRFToken': csrftoken},
        body: JSON.stringify({'nOid': nOid, 'oid': 'mystauth.com'})
    }).then(response => response.json())
      .then(async (data) => {
          if (data['success'])
          {
            document.getElementById("api_id").innerHTML = data["id"];
            document.getElementById("api_key").innerHTML = data["apiKey"];
            document.getElementById("input").setAttribute("hidden", "none");
            document.getElementById("data").removeAttribute("hidden");
            setTimeout(function() { document.getElementById("data_button").disabled = false;}, 10000);
          }
          else
          {
            notify(data['info'], 0);
            if (data['info'].includes("Time"))
            {
              window.location.href = "/dash";
            }
          }
      });
  }
});


function onlySpaces(str)
{
  return str.replace(/\s/g, '').length == 0;
}

function notify(str, type) {
  let notif = document.getElementById('notif');
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
