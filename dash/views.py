from django.shortcuts import render, redirect
from .models import Acc
from mystauth.models import Origin

# Create your views here.
def dash(request):
    if request.authenticated:
        usr = request.GET.get('usr')
        data = {'usr': usr, 'auth_token': request.token}
        if Acc.objects.filter(user=usr).exists():
            getUser = Acc.objects.get(user=usr)
            oid = getUser.oid
            getOrigin = Origin.objects.get(oid=oid)
            data['id'] = getOrigin.uid
            data['oid'] = oid
            data['rid'] = getOrigin.rid
            data['ttl'] = getOrigin.ttl
            data['bioOnly'] = str(getOrigin.bioOnly)
            data['userCount'] = getOrigin.userCount
            data['apiTokens'] = getOrigin.apiTokens
            return render(request, "dash2.html", data)
        else:
            return render(request, "dash.html", data)
    elif request.info == "Login Timed Out!":
        usr = request.GET.get('usr')
        return redirect('https://mystauth.com/auth/?rid=0e3b8c98b34e43a5885e41061d15bce2&img=RdELgb1bNz8&usr='+usr+'&ref=https://mystauth.com/dash#login')
    else:
        return render(request, "block.html")
