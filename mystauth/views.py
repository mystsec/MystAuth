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
from .crypto import (
    getUID,
    getHashMat,
    byTob64,
    b64Toby,
    b642str,
    b64url_to_b64,
    HASH,
    authenticate,
    validateToken,
    authenticateToken,
    generateToken,
    tokenExchange,
    newOrigin,
    checkURL,
    getRedirectURL,
    sigKeyIDs,
    sigPath,
)
import os
import json
import re

# Create your views here.
def doc(request):
    return render(request, "doc.html")

def terms(request):
    return redirect('https://mystauth.com/docs/#terms')

def privacy(request):
    return render(request, "privacy.html")

def oidcConfig(request):
    config = {}
    config["issuer"] = "https://mystauth.com"
    config["authorization_endpoint"] = "https://mystauth.com/authorize"
    config["token_endpoint"] = "https://mystauth.com/api/v1/user/token/verify"
    config["jwks_uri"] = "https://mystauth.com/api/v1/certs"
    config["scopes_supported"] = ["openid", "username"]
    config["response_types_supported"] = ["code"]
    config["subject_types_supported"] = ["pairwise"]
    config["id_token_signing_alg_values_supported"] = ["RS256"]
    config["ui_locales_supported"] = ["en-US", "en-CA"]
    config["display_values_supported"] = ["page", "popup"]
    config["op_policy_uri"] = "https://mystauth.com/privacy"
    config["op_tos_uri"] = "https://mystauth.com/terms"
    return JsonResponse(config)

def oidcSigningCerts(request):
    certs = {}
    keys = []
    for id in sigKeyIDs:
        key = {}
        key["kty"] = "RSA"
        key["alg"] = "RS256"
        key["use"] = "sig"
        key["kid"] = id
        with open(sigPath+'public_key_'+id+'.pem', 'r') as pbk_file:
            pem = pbk_file.read().replace('\n', '')
        key["pem"] = pem
        keys.append(key)
    certs["keys"] = keys
    return JsonResponse(certs)

def oidcAuth(request):
    required_params = ['scope', 'client_id', 'response_type', 'redirect_uri', 'state']
    if request.method == 'GET' and all(key in request.GET for key in required_params):
        rid = request.GET.get('client_id')
        ref = request.GET.get('redirect_uri')
        return authPage(request, rid, ref)
    else:
        return render(request, "block.html")

def originAuth(request):
    if request.method == 'GET' and 'rid' in request.GET and 'ref' in request.GET:
        rid = request.GET.get('rid')
        ref = request.GET.get('ref')
        return authPage(request, rid, ref)
    else:
        return render(request, 'block.html')

def authPage(request, rid, ref):
    try:
        getOrigin = Origin.objects.get(rid=rid)
        oid = getattr(getOrigin, 'oid')
    except:
        return render(request, 'block.html')

    checkRef = checkURL(ref, oid)

    if checkRef:
        data = {'bioOnly': str(getOrigin.bioOnly)}
        if 'pbk' in request.GET and 'state' in request.GET:
            data['eks'] = 'True'
            if 'noFallback' in request.GET:
                data['eksF'] = 'False'
            else:
                data['eksF'] = 'True'
        else:
            data['eks'] = 'False'
        if 'img' in request.GET:
            data['img'] = re.sub(r'[^a-zA-Z0-9_-]', '', request.GET.get('img'))
        elif 'bgclr' in request.GET:
            data['bgclr'] = re.sub(r'[^a-zA-Z0-9]', '', request.GET.get('bgclr'))
        if 'clr' in request.GET:
            data['clr'] = re.sub(r'[^a-zA-Z0-9]', '', request.GET.get('clr'))
        if 'hovclr' in request.GET:
            data['hovclr'] = re.sub(r'[^a-zA-Z0-9]', '', request.GET.get('hovclr'))
        if 'display' in request.GET and request.GET.get('display') == "popup":
            data['display'] = 'popup'
        if 'usr' in request.GET:
            data['usr'] = re.sub(r'[^a-zA-Z0-9_-]', '', request.GET.get('usr'))
        elif oid in request.COOKIES:
            data['usr'] = request.COOKIES.get(oid)
        if 'rst' in request.GET:
            rst = request.GET.get('rst')
            checkRst = checkURL(rst, oid)
            if checkRst:
                data['reset'] = re.sub(r'[^a-zA-Z0-9_%/:#&=?.-]', '', rst)
        data['ref'] = re.sub(r'[^a-zA-Z0-9_%/:#&=?.-]', '', ref)
        data['rid'] = rid
        return render(request, 'originAuth.html', data)
    else:
        return render(request, 'block.html')

def resetAuth(request):
    if request.method == 'GET' and 'rid' in request.GET and 'ref' in request.GET and 'mc' in request.GET and 'usr' in request.GET:
        rid = request.GET.get('rid')
        ref = request.GET.get('ref')
        mc = request.GET.get('mc')
        usr = request.GET.get('usr')

        try:
            getOrigin = Origin.objects.get(rid=rid)
            oid = getattr(getOrigin, 'oid')
        except:
            return render(request, 'block.html')

        checkRef = checkURL(ref, oid)

        if checkRef:
            auth = authenticateToken(oid, usr, mc, 600, True, True)
            if auth['success']:
                data = {'bioOnly': str(getOrigin.bioOnly)}
                if 'pbk' in request.GET and 'state' in request.GET:
                    data['eks'] = 'True'
                    if 'noFallback' in request.GET:
                        data['eksF'] = 'False'
                    else:
                        data['eksF'] = 'True'
                else:
                    data['eks'] = 'False'
                if 'img' in request.GET:
                    data['img'] = re.sub(r'[^a-zA-Z0-9_-]', '', request.GET.get('img'))
                elif 'bgclr' in request.GET:
                    data['bgclr'] = re.sub(r'[^a-zA-Z0-9]', '', request.GET.get('bgclr'))
                if 'clr' in request.GET:
                    data['clr'] = re.sub(r'[^a-zA-Z0-9]', '', request.GET.get('clr'))
                if 'hovclr' in request.GET:
                    data['hovclr'] = re.sub(r'[^a-zA-Z0-9]', '', request.GET.get('hovclr'))
                data['usr'] = re.sub(r'[^a-zA-Z0-9_-]', '', request.GET.get('usr'))
                data['ref'] = re.sub(r'[^a-zA-Z0-9_%/:#&=?.-]', '', ref)
                data['token'] = auth['token']
                return render(request, 'resetAuth.html', data)
            elif 'Time' in auth['info']:
                return render(request, 'msg.html', {'msg': 'Reset Link Timed Out, Please Request a New One!'})
            else:
                return render(request, 'msg.html', {'msg': 'Reset Link No Longer Valid, Please Request a New One!'})
        else:
            return render(request, 'block.html')
    else:
        return render(request, 'block.html')

def userRegOpts(request):
    body = json.loads(request.body.decode('utf-8'))
    username = body['usr']
    rid = body['rid']
    eks = body['eks']

    if len(username) > 255:
        return JsonResponse(['failed', 'Username must be less than 255 characters!'], safe=False)

    if not re.match("^[a-zA-Z0-9_-]+$", username):
        return JsonResponse(['failed', 'Only Alphanumerics, Underscore, and Hyphen Allowed in Username'], safe=False)

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')

    if getOrigin.apiTokens <= 0:
        return JsonResponse(['failed', 'Contact site admin! Err: api_token_limit'], safe=False)

    if Auth.objects.filter(user=username, oid=oid).exists():
        result = ['failed', 'Username already taken!']
    else:
        uuid = getUID()

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
            rp_name="Myst Auth - "+oid,
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

        if eks:
            opt_dict["extensions"] = {"largeBlob": {"support": "preferred"}}
            json_dict = json.dumps(opt_dict)

        newAuth = Auth(user=username, uid=uuid, challenge=opt_dict["challenge"], oid=oid)
        newAuth.save()

        return JsonResponse(json_dict, safe=False)
    return JsonResponse(result, safe=False)

def regDrop(request):
    body = json.loads(request.body.decode('utf-8'))
    username = body['usr']
    rid = body['rid']
    uid = body['uid']

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')

    if Auth.objects.filter(user=username, uid=uid, oid=oid).exists():
        auth = Auth.objects.get(user=username, uid=uid, oid=oid)
        if auth.pbk == '':
            auth.delete()

    return JsonResponse({'success': True}, safe=False)

def resetRegOpts(request):
    body = json.loads(request.body.decode('utf-8'))
    username = body['usr']
    rid = body['rid']
    mc = body['mc']

    if not re.match("^[a-zA-Z0-9_-]+$", username):
        return JsonResponse(['failed', 'Only Alphanumerics, Underscore, and Hyphen Allowed in Username'], safe=False)

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')

    try:
        getUser = Auth.objects.get(user=username, oid=oid)
    except:
        return JsonResponse(['failed', 'Reset Link Timed Out, Please Request a New One!'], safe=False)

    auth = authenticateToken(oid, username, mc, 180, True, True)

    if auth['success']:
        uuid = getUser.uid
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
            rp_name="Myst Auth - "+oid,
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

        getUser.challenge = opt_dict["challenge"]
        getUser.save()

        return JsonResponse([json_dict, auth['token']], safe=False)
    elif "Time" in auth['info']:
        return JsonResponse(['failed', 'Session Timed Out! Request New Reset Link'], safe=False)
    else:
        return JsonResponse(['failed', 'Reset Link Not Valid, Please Request a New One!'], safe=False)

def userRegister(request):
    body = json.loads(request.body.decode('utf-8'))
    response = RegistrationCredential.parse_raw(json.dumps(body['resp']))
    uid = body['uid']
    rid = body['rid']
    ref = body['ref']

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')

    getUser = Auth.objects.get(uid=uid)
    usr = getUser.user

    if not checkURL(ref, oid):
        Auth.objects.get(user=usr, oid=oid).delete()
        return JsonResponse(['failed', 'Unsecure Login! Please Reload and Try Again!'], safe=False)

    eChallenge = getattr(getUser, 'challenge')
    eChallenge = base64url_to_bytes(eChallenge)

    try:
        reg_verification = verify_registration_response(
            credential=response,
            expected_challenge=eChallenge,
            expected_origin=f"https://{request.get_host()}",
            expected_rp_id="mystauth.com",
        )
    except:
        Auth.objects.get(user=usr, oid=oid).delete()
        return JsonResponse(['failed', 'Passkey Verification Failed!'], safe=False)

    cid = reg_verification.credential_id
    pbk = reg_verification.credential_public_key
    getUser.credId = byTob64(cid)
    getUser.pbk = byTob64(pbk)
    if 'fdata' in body:
        getUser.fdata = body['fdata']
    getUser.save()

    getOrigin.userCount = getOrigin.userCount + 1
    getOrigin.apiTokens = getOrigin.apiTokens - 1
    getOrigin.save()
    redirectURL = getRedirectURL(ref, usr, oid, body)
    resp = JsonResponse(['success', redirectURL], safe=False)
    resp.set_cookie(oid, usr, samesite='Lax', secure=True, httponly=True)
    return resp

def resetRegister(request):
    body = json.loads(request.body.decode('utf-8'))
    response = RegistrationCredential.parse_raw(json.dumps(body['resp']))
    uid = body['uid']
    rid = body['rid']
    mc = body['mc']
    ref = body['ref']

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')

    getUser = Auth.objects.get(uid=uid)
    usr = getUser.user

    if not checkURL(ref, oid):
        return JsonResponse(['failed', 'Unsecure Login! Please Reload and Try Again!'], safe=False)

    auth = authenticateToken(oid, usr, mc, 45, True)

    if auth['success']:
        eChallenge = getattr(getUser, 'challenge')
        eChallenge = base64url_to_bytes(eChallenge)

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
        getUser.credId = byTob64(cid)
        getUser.pbk = byTob64(pbk)
        getUser.signCount = 0
        getUser.save()

        redirectURL = getRedirectURL(ref, usr, oid, body)
        resp = JsonResponse(['success', redirectURL], safe=False)
        resp.set_cookie(oid, usr, samesite='Lax', secure=True, httponly=True)
        return resp
    elif 'Time' in auth['info']:
        return JsonResponse(['failed', 'Session Timed Out! Request New Reset Link'], safe=False)
    else:
        return JsonResponse(['failed', 'Authentication Failed'], safe=False)

def userAuthOpts(request):
    body = json.loads(request.body.decode('utf-8'))
    username = body['usr']
    rid = body['rid']
    eks = body['eks']

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
        if eks:
            opt_dict["extensions"] = {"largeBlob": {"read": True}}
            opt_dict["fdata"] = user.fdata
            json_dict = json.dumps(opt_dict)

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
    ref = body['ref']

    getOrigin = Origin.objects.get(rid=rid)
    oid = getattr(getOrigin, 'oid')

    if not checkURL(ref, oid):
        return JsonResponse(['failed', 'Unsecure Login! Please Reload and Try Again!'], safe=False)

    getUser = Auth.objects.get(user=username, oid=oid)
    eChallenge = getattr(getUser, 'challenge')
    eChallenge = base64url_to_bytes(eChallenge)


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

    redirectURL = getRedirectURL(ref, usr, oid, body)
    resp = JsonResponse(['success', redirectURL], safe=False)
    resp.set_cookie(oid, usr, samesite='Lax', secure=True, httponly=True)
    return resp

def editOrigin(request):
    body = json.loads(request.body.decode('utf-8'))
    id = body['id']
    apiKey = body['apiKey']
    auth = authenticate(id, apiKey)
    if auth[0]:
        oid = auth[1]
        usr = request.COOKIES.get('myst_usr')
        token = request.COOKIES.get('myst_token')

        auth2 = authenticateToken("mystauth.com", usr, token, auth[2])
        if auth2['success']:
            newOid = body['oid']
            ttl = body['ttl']
            bioOnly = body['bioOnly'] == "True"
            allowReset = body['allowReset'] == "True"
            if oid != newOid and Origin.objects.filter(oid=newOid).exists():
                result = {'success': False, 'info': 'Origin already taken! If you own this domain, please contact us.'}
            elif not isinstance(ttl, int) or ttl < 0:
                result = {'success': False, 'info': 'TTL must be a positive Integer, without other characters.'}
            else:
                auth = Origin.objects.get(oid=oid)
                auth.oid = newOid
                auth.ttl = ttl
                auth.bioOnly = bioOnly
                auth.allowReset = allowReset
                auth.save()
                getAcc = Acc.objects.get(user=usr, oid=oid)
                getAcc.oid = newOid
                getAcc.save()
                result = {'success': True, 'oid': newOid, 'ttl': ttl, 'bioOnly': str(bioOnly), 'allowReset': str(allowReset)}
            response = JsonResponse(result, safe=False)
            response.set_cookie('myst_token', auth2['token'], samesite='Lax', secure=True, httponly=True)
            return response
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
        usr = request.COOKIES.get('myst_usr')
        token = request.COOKIES.get('myst_token')

        auth2 = authenticateToken("mystauth.com", usr, token, auth[2])
        if auth2['success']:
            hashMat = getHashMat()
            hash = HASH(hashMat["salt"], hashMat["uuid"])

            origin = Origin.objects.get(oid=oid)
            origin.uuid = hash
            origin.salt = hashMat["salt"]
            origin.save()

            response = JsonResponse({'success': True, 'apiKey': hashMat["uuid"]}, safe=False)
            response.set_cookie('myst_token', auth2['token'], samesite='Lax', secure=True, httponly=True)
            return response
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
        usr = request.COOKIES.get('myst_usr')
        token = request.COOKIES.get('myst_token')

        auth2 = authenticateToken("mystauth.com", usr, token, auth[2])
        if auth2['success']:
            Origin.objects.get(oid=oid).delete()
            Acc.objects.get(user=usr, oid=oid).delete()

            response = JsonResponse({'success': True}, safe=False)
            response.set_cookie('myst_token', auth2['token'], samesite='Lax', secure=True, httponly=True)
            return response
        else:
            return JsonResponse(auth2, safe=False)
    else:
        return JsonResponse({'success': False, 'info': 'API Authentication Failed!'}, safe=False)

@csrf_exempt
def newResetLink(request):
    body = json.loads(request.body.decode('utf-8'))
    id = body['id']
    apiKey = body['apiKey']
    origin = Origin.objects.get(uid=id)
    if origin.allowReset:
        auth = authenticate(id, apiKey)
        if auth[0]:
            usr = body['usr']
            oid = auth[1]
            mc = generateToken(oid, usr, 600, rst=True)
            return JsonResponse({'success': True, 'mcode': mc}, safe=False)
        else:
            return JsonResponse({'success': False, 'info': 'API Authentication Failed!'}, safe=False)
    else:
        return JsonResponse({'success': False, 'info': 'allowReset set to False, change in API Account Dashboard'}, safe=False)

@csrf_exempt
def delAccount(request):
    body = json.loads(request.body.decode('utf-8'))
    id = body['id']
    apiKey = body['apiKey']
    auth = authenticate(id, apiKey)
    if auth[0]:
        try:
            usr = body['usr']
            oid = auth[1]
            tokenAuth = validateToken(oid, usr, body['token'])
            token = tokenAuth['token']
            if tokenAuth['auth_check']:
                if tokenAuth['time_check']:
                    token.delete()
                    user = Auth.objects.get(user=usr, oid=oid).delete()
                    getOrigin = Origin.objects.get(oid=oid)
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

@csrf_exempt
def verifyToken(request):
    body = json.loads(request.body.decode('utf-8'))
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if auth_header and auth_header.startswith('Basic '):
        pair = b642str(b64url_to_b64(auth_header.split(' ')[1])).split(":")
        id = pair[0]
        apiKey = pair[1]
    elif 'client_id' in body and 'client_secret' in body:
        id = body['client_id']
        apiKey = body['client_secret']
    else:
        id = body['id']
        apiKey = body['apiKey']
    auth = authenticate(id, apiKey)
    if auth[0]:
        return JsonResponse(tokenExchange(body, auth), safe=False)
    else:
        return JsonResponse({'success': False, 'info': 'API Authentication Failed!'}, safe=False)

def newOriginAPI(request):
    body = json.loads(request.body.decode('utf-8'))
    oid = body['oid']
    nOid = body['nOid']
    usr = request.COOKIES.get('myst_usr')
    token = request.COOKIES.get('myst_token')
    auth = authenticateToken("mystauth.com", usr, token, 3600)
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

        if result['success']:
            newAcc = Acc(user=usr, oid=nOid)
            newAcc.save()

        response = JsonResponse(result, safe=False)
        response.set_cookie('myst_token', auth['token'], samesite='Lax', secure=True, httponly=True)
    else:
        result = {'success': False, 'info': auth['info']}
        response = JsonResponse(result, safe=False)
    return response
