function checkCookieSupport() {
  return navigator.cookieEnabled;
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

function noPasskeySupport()
{
  document.getElementById("loading_msg").innerHTML = "Your Device/Browser Doesn't Support <a href='https://blog.google/inside-google/googlers/ask-a-techspert/how-passkeys-work/' target='_blank'>Passkeys</a> 😢 <br><br><a href='https://passkeys.dev/device-support/#matrix' target='_blank'>Check Support</a>";
  loading();
}

function noCookieSupport()
{
  document.getElementById("loading_msg").innerHTML = "Please Enable Cookies <br><br> <a href='https://mystauth.com/privacy/#kix.sbkz6l6dox82' target='_blank'>Only used to Identify and Secure Account</a>";
  loading();
}

function onlySpaces(str)
{
  return str.replace(/\s/g, '').length == 0;
}

function prepURL(url)
{
  url = decodeURIComponent(url)
  return url.replace(/"/g, "%22").replace(/'/g, "%27").replace(/</g, "%3C").replace(/>/g, "%3E")
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
