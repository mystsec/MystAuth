from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import Acc
from mystauth.models import Origin

# Create your views here.
def signout(request):
    response = JsonResponse({'success': True}, safe=False)
    response.delete_cookie('myst_usr')
    response.delete_cookie('myst_token')
    return response

def dash(request):
    if request.authenticated:
        usr = request.user
        data = {'usr': usr}
        if Acc.objects.filter(user=usr).exists():
            getUser = Acc.objects.get(user=usr)
            oid = getUser.oid
            getOrigin = Origin.objects.get(oid=oid)
            data['id'] = getOrigin.uid
            data['oid'] = oid
            data['rid'] = getOrigin.rid
            data['ttl'] = getOrigin.ttl
            data['bioOnly'] = str(getOrigin.bioOnly)
            data['allowReset'] = str(getOrigin.allowReset)
            data['userCount'] = getOrigin.userCount
            data['apiTokens'] = getOrigin.apiTokens
            response = render(request, "dash2.html", data)
            response.set_cookie('myst_usr', usr, samesite='Lax', secure=True, httponly=True)
            response.set_cookie('myst_token', request.token, samesite='Lax', secure=True, httponly=True)
        else:
            response = render(request, "dash.html", data)
            response.set_cookie('myst_usr', usr, samesite='Lax', secure=True, httponly=True)
            response.set_cookie('myst_token', request.token, samesite='Lax', secure=True, httponly=True)
        request.user = ""
        request.token = ""
        request.authenticated = ""
        return response
    elif request.info == "Login Timed Out!":
        return redirect('https://mystauth.com/auth/?rid=0e3b8c98b34e43a5885e41061d15bce2&img=RdELgb1bNz8&usr='+usr+'&ref=https://mystauth.com/dash#login')
    else:
        return redirect('https://mystauth.com/auth/?rid=0e3b8c98b34e43a5885e41061d15bce2&img=RdELgb1bNz8&ref=https://mystauth.com/dash#login')
