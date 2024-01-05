from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import Auth, Origin, Token
from dash.models import Acc
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    UserVerificationRequirement,
)
import secrets
import hashlib
import os
import base64
import uuid
from urllib.parse import urlparse, unquote
import json
import datetime
import pytz
import re

# Create your views here.
def doc(request):
    return render(request, "doc.html")

def terms(request):
    return redirect('https://mystauth.com/docs/#terms')

def privacy(request):
    return render(request, "privacy.html")

def originAuth(request):
    if request.method == 'GET' and 'rid' in request.GET and 'ref' in request.GET:
        rid = request.GET.get('rid')
        ref = request.GET.get('ref')

        try:
            getOrigin = Origin.objects.get(rid=rid)
            oid = getattr(getOrigin, 'oid')
        except:
            return render(request, 'block.html')

        url = urlparse(unquote(ref))
        origin = url.hostname
        scheme = url.scheme

        if scheme == 'https' and origin == oid:
            if getOrigin.apiTokens != 0:
                data = {'bioOnly': str(getOrigin.bioOnly)}
                if 'img' in request.GET:
                    data['img'] = request.GET.get('img')
                elif 'bgclr' in request.GET:
                    data['bgclr'] = request.GET.get('bgclr')
                if 'clr' in request.GET:
                    data['clr'] = request.GET.get('clr')
                if 'hovclr' in request.GET:
                    data['hovclr'] = request.GET.get('hovclr')
                return render(request, 'originAuth.html', data)
            else:
                return render(request, 'block.html')
        else:
            return render(request, 'block.html')
    else:
        return render(request, 'block.html')

def userRegOpts(request):
    body = json.loads(request.body.decode('utf-8'))
    username = body['usr']
    rid = body['rid']

    if not re.match("^[a-zA-Z0-9_-]+$", username):
        return JsonResponse(['failed', 'Only Alphanumerics, Underscore, and Hyphen Allowed in Username'], safe=False)

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')

    if Auth.objects.filter(user=username, oid=oid).exists():
        result = ['failed', 'Username already taken!']
    else:
        uuid = getUUIDStr()
        while Auth.objects.filter(uid=uuid).exists():
            uuid = getUUIDStr()

        bioOnly = getOrigin.bioOnly
        if bioOnly:
            auth_sel = AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.PREFERRED,
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            )
        else:
            auth_sel = AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            )

        regOpts = generate_registration_options(
            rp_id="mystauth.com",
            rp_name="Myst Auth",
            user_id=uuid,
            user_name=username,
            user_display_name=username,
            attestation=AttestationConveyancePreference.DIRECT,
            authenticator_selection=auth_sel,
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_512, COSEAlgorithmIdentifier.ECDSA_SHA_256, COSEAlgorithmIdentifier.EDDSA, COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256],
            timeout=60000,
        )
        json_dict = options_to_json(regOpts)
        opt_dict = json.loads(json_dict)

        newAuth = Auth(user=username, uid=uuid, challenge=opt_dict["challenge"], oid=oid)
        newAuth.save()

        return JsonResponse(json_dict, safe=False)
    return JsonResponse(result, safe=False)

def userRegister(request):
    body = json.loads(request.body.decode('utf-8'))
    response = RegistrationCredential.parse_raw(json.dumps(body['resp']))
    uid = body['uid']
    rid = body['rid']

    getUser = Auth.objects.get(uid=uid)
    eChallenge = getattr(getUser, 'challenge')
    eChallenge = base64url_to_bytes(eChallenge)
    eChallenge = base64url_to_bytes(b64_to_b64url(byTob64(eChallenge)))

    try:
        reg_verification = verify_registration_response(
            credential=response,
            expected_challenge=eChallenge,
            expected_origin=f"https://{request.get_host()}",
            expected_rp_id="mystauth.com",
        )
    except:
        return JsonResponse(['failed', 'Passkey Verification Failed!'], safe=False)

    cid = reg_verification.credential_id
    pbk = reg_verification.credential_public_key
    usr = getUser.user
    getUser.credId = byTob64(cid)
    getUser.pbk = byTob64(pbk)
    getUser.save()

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')
    getOrigin.userCount = getOrigin.userCount + 1
    getOrigin.apiTokens = getOrigin.apiTokens - 1
    getOrigin.save()
    token = generateToken(oid, usr, 45)
    return JsonResponse(['success', token], safe=False)

def userAuthOpts(request):
    body = json.loads(request.body.decode('utf-8'))
    username = body['usr']
    rid = body['rid']

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')

    user = Auth.objects.filter(user=username, oid=oid)
    if user.exists():
        user = user.first()
        cid = getattr(user, 'credId')

        authOpts = generate_authentication_options(
            rp_id="mystauth.com",
            timeout=60000,
            allow_credentials=[PublicKeyCredentialDescriptor(id=b64Toby(cid))],
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        json_dict = options_to_json(authOpts)
        opt_dict = json.loads(json_dict)

        user.challenge = opt_dict["challenge"]
        user.save()
        return JsonResponse(json_dict, safe=False)
    else:
        result = ['failed', 'Incorrect Username!']
    return JsonResponse(result, safe=False)

def userAuthenticate(request):
    body = json.loads(request.body.decode('utf-8'))
    response = AuthenticationCredential.parse_raw(json.dumps(body['resp']))
    username = body['usr']
    rid = body['rid']

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')

    getUser = Auth.objects.get(user=username, oid=oid)
    eChallenge = getattr(getUser, 'challenge')
    eChallenge = base64url_to_bytes(eChallenge)
    eChallenge = base64url_to_bytes(b64_to_b64url(byTob64(eChallenge)))


    pbk = getattr(getUser, 'pbk')
    pbk = b64Toby(pbk)

    try:
        auth_verification = verify_authentication_response(
            credential=response,
            expected_challenge=eChallenge,
            expected_rp_id="mystauth.com",
            expected_origin="https://mystauth.com",
            credential_public_key=pbk,
            credential_current_sign_count=getUser.signCount,
        )
    except:
        return JsonResponse(['failed', 'Authentication Failed!'], safe=False)

    getUser.signCount = auth_verification.new_sign_count
    usr = getUser.user
    getUser.save()

    token = generateToken(oid, usr, 45)
    return JsonResponse(['success', token], safe=False)

def editOrigin(request):
    body = json.loads(request.body.decode('utf-8'))
    id = body['id']
    apiKey = body['apiKey']
    auth = authenticate(id, apiKey)
    if auth[0]:
        oid = auth[1]
        usr = body['usr']
        token = body['token']

        auth2 = authenticateToken("mystauth.com", usr, token)
        print(auth2)
        if auth2['success']:
            newOid = body['oid']
            ttl = body['ttl']
            bioOnly = body['bioOnly'] == "True"
            print(bioOnly)
            if oid != newOid and Origin.objects.filter(oid=newOid).exists():
                result = {'success': False, 'info': 'Origin already taken!', 'token': auth2['token']}
            else:
                auth = Origin.objects.get(oid=oid)
                auth.oid = newOid
                auth.ttl = ttl
                auth.bioOnly = bioOnly
                auth.save()
                getAcc = Acc.objects.get(user=usr, oid=oid)
                getAcc.oid = newOid
                getAcc.save()
                result = {'success': True, 'oid': newOid, 'ttl': ttl, 'bioOnly': str(bioOnly), 'token': auth2['token']}
            return JsonResponse(result, safe=False)
        else:
            return JsonResponse(auth2, safe=False)
    else:
        return JsonResponse({'success': False, 'info': 'API Authentication Failed!'}, safe=False)

def cycleAPI(request):
    body = json.loads(request.body.decode('utf-8'))
    id = body['id']
    apiKey = body['apiKey']
    auth = authenticate(id, apiKey)
    if auth[0]:
        oid = auth[1]
        usr = body['usr']
        token = body['token']

        auth2 = authenticateToken("mystauth.com", usr, token)
        if auth2['success']:
            uuid = secrets.token_hex(64)
            salt = secrets.token_bytes(64)
            hash = ''
            hash = PBKDF2_HASH(salt, uuid)

            origin = Origin.objects.get(oid=oid)
            origin.uuid = hash
            origin.salt = salt
            origin.save()

            result = {'success': True, 'apiKey': uuid, 'token': auth2['token']}
            return JsonResponse(result, safe=False)
        else:
            return JsonResponse(auth2, safe=False)
    else:
        return JsonResponse({'success': False, 'info': 'API Authentication Failed!'}, safe=False)

def delAPI(request):
    body = json.loads(request.body.decode('utf-8'))
    id = body['id']
    apiKey = body['apiKey']
    auth = authenticate(id, apiKey)
    if auth[0]:
        oid = auth[1]
        usr = body['usr']
        token = body['token']

        auth2 = authenticateToken("mystauth.com", usr, token)
        if auth2['success']:
            Origin.objects.get(oid=oid).delete()
            Acc.objects.get(user=usr, oid=oid).delete()

            result = {'success': True, 'token': auth2['token']}
            return JsonResponse(result, safe=False)
        else:
            return JsonResponse(auth2, safe=False)
    else:
        return JsonResponse({'success': False, 'info': 'API Authentication Failed!'}, safe=False)

@csrf_exempt
def delAccount(request):
    body = json.loads(request.body.decode('utf-8'))
    id = body['id']
    apiKey = body['apiKey']
    auth = authenticate(id, apiKey)
    if auth[0]:
        try:
            usr = body['usr']
            key = body['token']
            oid = auth[1]
            origin = Origin.objects.get(oid=oid)
            token = Token.objects.get(user=usr, oid=oid)
            salt = getattr(token, 'salt')
            hash = getattr(token, 'hash')
            ot = getattr(token, 'timestamp')
            ttl = getattr(token, 'ttl')
            ct = datetime.datetime.now().replace(tzinfo=pytz.UTC)
            td = ct - ot
            hashed = PBKDF2_HASH(salt, key)
            authCheck = str(hashed) == str(hash)
            timeCheck = td.seconds < ttl
            if authCheck:
                if timeCheck:
                    token.delete()
                    user = Auth.objects.get(user=usr, oid=oid).delete()
                    getOrigin = Origin.objects.get(rid=rid)
                    oid = getattr(getOrigin, 'oid')
                    getOrigin.userCount = getOrigin.userCount - 1
                    getOrigin.apiTokens = getOrigin.apiTokens + 1
                    getOrigin.save()
                    return JsonResponse({'success': True}, safe=False)
                else:
                    token.delete()
                    return JsonResponse({'success': False, 'info': 'Login Timed Out!'}, safe=False)
            else:
                return JsonResponse({'success': False, 'info': 'Authentication Failed!'}, safe=False)
        except:
            return JsonResponse({'success': False, 'info': 'Authentication Failed!'}, safe=False)
    else:
        return JsonResponse({'success': False, 'info': 'API Authentication Failed!'}, safe=False)

#Authenticates Origin Key
def authenticate(id, uuid):
    get = Origin.objects.get(uid = id)
    hash = getattr(get, 'uuid')
    salt = getattr(get, 'salt')
    oid = getattr(get, 'oid')
    hashed = PBKDF2_HASH(salt, uuid)
    return [str(hashed) == str(hash), oid]

@csrf_exempt
def verifyToken(request):
    body = json.loads(request.body.decode('utf-8'))
    id = body['id']
    apiKey = body['apiKey']
    auth = authenticate(id, apiKey)
    if auth[0]:
        usr = body['usr']
        key = body['token']
        oid = auth[1]
        return JsonResponse(authenticateToken(oid, usr, key), safe=False)
    else:
        return JsonResponse({'success': False, 'info': 'API Authentication Failed!'}, safe=False)

#Authenticates Auth Token
def authenticateToken(oid, usr, key):
    try:
        origin = Origin.objects.get(oid=oid)
        token = Token.objects.get(user=usr, oid=oid)
        salt = getattr(token, 'salt')
        hash = getattr(token, 'hash')
        ot = getattr(token, 'timestamp')
        ttl = getattr(token, 'ttl')
        pst = pytz.timezone('America/Los_Angeles')
        ct = pst.localize(datetime.datetime.now())
        td = ct - ot
        hashed = PBKDF2_HASH(salt, key)
        authCheck = str(hashed) == str(hash)
        timeCheck = td.seconds < ttl
        if authCheck:
            if timeCheck:
                token.delete()
                newToken = generateToken(oid, usr, origin.ttl)
                return {'success': True, 'token': newToken}
            else:
                token.delete()
                return {'success': False, 'info': 'Login Timed Out!'}
        else:
            return {'success': False, 'info': 'Authentication Failed!'}
    except:
        return {'success': False, 'info': 'Authentication Failed!'}

def newOriginAPI(request):
    body = json.loads(request.body.decode('utf-8'))
    oid = body['oid']
    nOid = body['nOid']
    usr = body['usr']
    token = body['token']
    auth = authenticateToken("mystauth.com", usr, token)
    if auth['success']:
        if 'ttl' in body and 'bioOnly' in body:
            ttl = body['ttl']
            bioOnly = body['bioOnly']
            result = newOrigin(nOid, ttl, bioOnly)
        elif 'ttl' in body:
            ttl = body['ttl']
            result = newOrigin(nOid, ttl)
        elif 'bioOnly' in body:
            bioOnly = body['bioOnly']
            result = newOrigin(nOid, bio_only=bioOnly)
        else:
            result = newOrigin(nOid)

        result['token'] = auth['token']

        if result['success']:
            newAcc = Acc(user=usr, oid=nOid)
            newAcc.save()
    else:
        result = {'success': False, 'info': auth['info']}
    return JsonResponse(result, safe=False)

#Generates new Origin
def newOrigin(oid, ttl=3600, bio_only=False):
    if Origin.objects.filter(oid=oid).exists():
        return {'success': False, 'info': 'Origin already taken! If you own this origin, please contact us.'}
    uuid = secrets.token_hex(64)
    salt = secrets.token_bytes(64)
    hash = ''
    hash = PBKDF2_HASH(salt, uuid)
    uid = getUUIDStr()
    while Origin.objects.filter(uid=uid).exists():
        uid = getUUIDStr()
    rid = getUUIDHex()
    while Origin.objects.filter(rid=rid).exists():
        rid = getUUIDHex()
    auth = Origin(uid = uid, uuid = hash, salt = salt, rid = rid, oid = oid, ttl = ttl, bioOnly = bio_only)
    auth.save()
    result = {'success': True, 'id': uid, 'apiKey': uuid, 'reqId': rid}
    print(result)
    return result

#Helper Fcts
def getUUIDStr():
    return str(uuid.uuid4())

def getUUIDHex():
    return uuid.uuid4().hex

def getRandomBytes(s):
    return os.urandom(s)

def PBKDF2_HASH(salt, plain):
    plain = plain.encode('utf-8')
    if isinstance(salt, str):
        salt = str2bytes(salt)
    hashed = hashlib.pbkdf2_hmac('sha512', plain, salt, 1000000)
    return base64.b64encode(hashed)

def str2bytes(byte_string):
    return eval(byte_string)

def generateToken(oid, usr, ttl=120):
    Token.objects.filter(user=usr, oid=oid).delete()
    uuid = secrets.token_hex(64)
    salt = secrets.token_bytes(64)
    hash = PBKDF2_HASH(salt, uuid)
    token = Token(oid=oid, user=usr, hash=hash, salt=salt, ttl=ttl)
    token.save()
    return uuid

def byTob64(bs):
    return base64.b64encode(bs).decode('utf-8')

def b64Toby(b6):
    return base64.b64decode(b6.encode('utf-8'))

def str2b64(s):
    return base64.b64encode(bytes(s, 'utf-8')).decode('utf-8')

def b642str(b6):
    return base64.b64decode(b6.encode('utf-8')).decode('utf-8')

def b64url_to_b64(str):
    return str.replace('-', '+').replace('_', '/')

def b64_to_b64url(str):
    return str.replace('+', '-').replace('/', '_').replace('=', '')
