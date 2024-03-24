from django.conf import settings
from .models import Auth, Origin, Token
import secrets
import hashlib
import fastpbkdf2
import argon2
import base64
import uuid
import datetime
import pytz
from urllib.parse import urlparse, unquote, urlencode, parse_qs, urlunparse
import re
from jwt import JWT, jwk_from_pem

#Initialize JWT util
jwtUtil = JWT()
sigKeyIDs = settings.JWT_SIG_KEYS
sigPath = settings.JWT_SIG_PATH

#Hashing Functions
def HASH(salt, plain, fct=1):
    if fct == 0:
        return PBKDF2_HASH(salt, plain)
    elif fct == 1:
        return PBKDF2_HASH_FAST(salt, plain)
    elif fct == 2:
        return PBKDF2_HASH_FAST_HEX(salt, plain)
    elif fct == 3:
        return ARGON2ID_HASH(salt, plain)
    else:
        return PBKDF2_HASH(salt, plain)

def PBKDF2_HASH(salt, plain):
    if isinstance(salt, str):
            salt = eval(salt)
    hashed = hashlib.pbkdf2_hmac('sha512', plain.encode('utf-8'), salt, 1000000)
    hashed = base64.b64encode(hashed)
    return hashed

def PBKDF2_HASH_HEX(salt, plain):
    if isinstance(salt, str):
            salt = eval(salt)
    hashed = hashlib.pbkdf2_hmac('sha512', plain.encode('utf-8'), salt, 1000000).hex()
    return hashed

def PBKDF2_HASH_FAST(salt, plain):
    if isinstance(salt, str):
            salt = eval(salt)
    hashed = fastpbkdf2.pbkdf2_hmac('sha512', plain.encode('utf-8'), salt, 1000000)
    hashed = base64.b64encode(hashed)
    return hashed

def PBKDF2_HASH_FAST_HEX(salt, plain):
    if isinstance(salt, str):
            salt = eval(salt)
    hashed = fastpbkdf2.pbkdf2_hmac('sha512', plain.encode('utf-8'), salt, 1000000).hex()
    return hashed

def ARGON2ID_HASH(salt, plain):
    if isinstance(salt, str):
            salt = eval(salt)
    hashed = argon2.low_level.hash_secret_raw(plain.encode('utf-8'), salt, time_cost=50, memory_cost=10000, parallelism=2, hash_len=64, type=argon2.low_level.Type.ID).hex()
    return hashed


#UUID & Random Generators
def getUUIDStr():
    return str(uuid.uuid4())

def getUID():
    uuid = getUUIDStr()
    while Auth.objects.filter(uid=uuid).exists():
        uuid = getUUIDStr()
    return uuid

def getUUIDHex():
    return uuid.uuid4().hex

def getState():
    return secrets.token_hex(32)


#Generate Hash Materials
def getHashMat():
    return {'uuid': secrets.token_hex(64), 'salt': secrets.token_bytes(64)}


#Checks Token Validity
def validateToken(oid, usr, key, erst=False, nrst=False):
    if len(str(key)) > 400:
        return {'auth_check': False, 'time_check': None, 'token': token}
    try:
        token = Token.objects.get(user__iexact=usr, rst=erst, oid=oid)
    except:
        return {'auth_check': False, 'time_check': None, 'token': token}
    salt = getattr(token, 'salt')
    hash = getattr(token, 'hash')
    ot = getattr(token, 'timestamp')
    ttl = getattr(token, 'ttl')
    rst = getattr(token, 'rst')
    if erst != rst:
        return {'auth_check': False, 'time_check': None, 'token': token}
    pst = pytz.timezone('America/Los_Angeles')
    ct = pst.localize(datetime.datetime.now())
    td = ct - ot
    hashed = HASH(salt, key)
    return {'auth_check': str(hashed) == str(hash), 'time_check': td.seconds < ttl, 'token': token}


#Checks Code Validity
def validateCode(oid, code):
    try:
        token = Token.objects.get(oid=oid, hash=code, salt="none", rst=False)
    except:
        return {'auth_check': False}
    ot = getattr(token, 'timestamp')
    ttl = getattr(token, 'ttl')
    pst = pytz.timezone('America/Los_Angeles')
    ct = pst.localize(datetime.datetime.now())
    td = ct - ot
    return {'auth_check': td.seconds < ttl, 'usr': getattr(token, 'user'), 'nonce': getattr(token, 'nonce'), 'token': token, 'key': getattr(token, 'key'), 'fkey': getattr(token, 'fkey'), 'fdata': getattr(token, 'edata')}


#Authenticates Auth Token
def authenticateToken(oid, usr, key, ottl, erst=False, nrst=False):
    try:
        auth = validateToken(oid, usr, key, erst, nrst)
        token = auth['token']
        if auth['auth_check']:
            if auth['time_check']:
                key = getattr(token, 'key')
                fkey = getattr(token, 'fkey')
                fdata = getattr(token, 'edata')
                token.delete()
                newToken = generateToken(oid, usr, ottl, nrst)
                return {'success': True, 'token': newToken, 'key': key, 'fkey': fkey, 'fdata': fdata}
            else:
                token.delete()
                return {'success': False, 'info': 'Login Timed Out!'}
        else:
            return {'success': False, 'info': 'Authentication Failed!'}
    except:
        return {'success': False, 'info': 'Authentication Failed!'}


#Authenticates Origin Key
def authenticate(id, uuid):
    get = Origin.objects.get(uid = id)
    hash = getattr(get, 'uuid')
    salt = getattr(get, 'salt')
    oid = getattr(get, 'oid')
    ttl = getattr(get, 'ttl')
    hashed = HASH(salt, uuid)
    return [str(hashed) == str(hash), oid, ttl]


#Handles Token Endpoint
def tokenExchange(body, auth):
    oid = auth[1]
    if 'grant_type' in body and 'code' in body:
        code_check = validateCode(oid, body['code'])
        if code_check['auth_check']:
            usr = code_check['usr']
            code_check['token'].delete()
            newToken = generateToken(oid, usr, auth[2])
            ret = {'access_token': newToken, 'token_type': 'Bearer', 'expires_in': auth[2]}
            if ('scope' in body and 'openid' in body['scope']) or 'scope' not in body:
                idToken = generateIdToken(oid, usr, auth[2], code_check['nonce'])
                ret['id_token'] = idToken
            if code_check['key'] != "":
                if code_check['key'] == 'False':
                    ret['key'] = False
                else:
                    ret['key'] = code_check['key']
            if code_check['fkey'] != "":
                ret['fkey'] = code_check['fkey']
            if code_check['fdata'] != "":
                ret['fdata'] = code_check['fdata']
        else:
            ret = {'success': False, 'info': 'Authentication Failed'}
    elif 'usr' in body and 'token' in body:
        usr = body['usr']
        key = body['token']
        token_check = authenticateToken(oid, usr, key, auth[2])
        if token_check['success']:
            ret = {'success': True, 'token': token_check['token'], 'access_token': token_check['token'], 'token_type': 'Bearer', 'expires_in': auth[2]}
            if ('scope' in body and 'openid' in body['scope']) or 'scope' not in body:
                idToken = generateIdToken(oid, usr, auth[2])
                ret['id_token'] = idToken
            if token_check['key'] != "":
                if token_check['key'] == 'False':
                    ret['key'] = False
                else:
                    ret['key'] = token_check['key']
            if token_check['fkey'] != "":
                ret['fkey'] = token_check['fkey']
            if token_check['fdata'] != "":
                ret['fdata'] = token_check['fdata']
        else:
            ret = token_check
    else:
        ret = {'success': False, 'info': 'Request Type not supported'}
    return ret


#Generate Auth Token
def generateToken(oid, usr, ttl=120, rst=False, key="", fkey="", edata=""):
    Token.objects.filter(user__iexact=usr, oid=oid, rst=rst).delete()
    hashMat = getHashMat()
    hash = HASH(hashMat["salt"], hashMat["uuid"])
    token = Token(oid=oid, user=usr, hash=hash, salt=hashMat["salt"], ttl=ttl, rst=rst, key=key, fkey=fkey, edata=edata)
    token.save()
    return hashMat["uuid"]


#Generate Auth Code
def generateCode(oid, usr, nonce, ttl=45, key="", fkey="", edata=""):
    Token.objects.filter(user__iexact=usr, oid=oid, rst=False).delete()
    code = secrets.token_hex(64)
    while Token.objects.filter(oid=oid, hash=code, salt="none").exists():
        code = secrets.token_hex(64)
    token = Token(oid=oid, user=usr, hash=code, salt="none", ttl=ttl, rst=False, key=key, fkey=fkey, edata=edata)
    token.save()
    return code

#Generates New Origin
def newOrigin(oid, ttl=3600, bio_only=False, hashFct=1):
    if Origin.objects.filter(oid=oid).exists():
        return {'success': False, 'info': 'Origin already taken! If you own this origin, please contact us.'}
    hashMat = getHashMat()
    hash = HASH(hashMat["salt"], hashMat["uuid"])
    uid = getUUIDStr()
    while Origin.objects.filter(uid=uid).exists():
        uid = getUUIDStr()
    rid = getUUIDHex()
    while Origin.objects.filter(rid=rid).exists():
        rid = getUUIDHex()
    auth = Origin(uid = uid, uuid = hash, salt = hashMat["salt"], rid = rid, oid = oid, ttl = ttl, bioOnly = bio_only, hashFct = hashFct)
    auth.save()
    result = {'success': True, 'id': uid, 'apiKey': hashMat["uuid"], 'reqId': rid}
    return result


#JWT/ID Token Functions
def generateJWT(dict):
    with open(sigPath+'private_key_'+sigKeyIDs[0]+'.pem', 'rb') as f:
        key = jwk_from_pem(f.read())
    jwt = jwtUtil.encode(dict, key, 'RS256', {'kid': sigKeyIDs[0]})
    return jwt

def generateIdToken(oid, usr, ttl, nonce=False):
    rid = Origin.objects.get(oid=oid).rid
    pst = pytz.timezone('America/Los_Angeles')
    now = pst.localize(datetime.datetime.now())
    iat = now.timestamp()
    exp = iat + ttl
    idDict = {}
    idDict['iss'] = 'https://mystauth.com'
    idDict['sub'] = usr
    idDict['aud'] = rid
    idDict['iat'] = iat
    idDict['exp'] = exp
    if nonce:
        idDict['nonce'] = nonce
    return generateJWT(idDict)


#URL Functions
def checkURL(url, host):
    url = urlparse(unquote(url))
    origin = url.hostname
    scheme = url.scheme
    return origin == host and scheme == 'https'

def getRedirectURL(url, usr, oid, body):
    url = prepURL(url)
    type = body['response_type']
    params = {}
    key = ""
    fkey = ""
    edata = ""
    if 'ekeys' in body:
        key = body['ekeys']
    if 'fkeys' in body:
        fkey = body['fkeys']
    if 'edata' in body:
        edata = body['edata']
    if 'eksUnavailable' in body:
        key = False
    if "code" in type:
        token = generateCode(oid, usr, body['nonce'], 45, key, fkey, edata)
        params['code'] = token
    elif "myst" in type:
        token = generateToken(oid, usr, 45, False, key, fkey, edata)
        params = {'usr': usr, 'token': token}
    else:
        params = {'error': 'invalid_request', 'error_description': 'Unsupported response_type value'}
    if 'state' in body:
        params['state'] = body['state']
    url = addURLParams(url, params)
    return url

def addURLParams(url, nparams):
    url = urlparse(url)
    params = parse_qs(url.query)
    params.update(nparams)
    params = urlencode(params, doseq=True)
    url = urlunparse(
        (url.scheme, url.netloc, url.path,
         url.params, params, url.fragment)
    )
    return url

def prepURL(url):
    url = unquote(url)
    return url.replace('"', "%22").replace("'", "%27").replace('<', "%3C").replace('>', "%3E")


#Helper Functions
def clearSpaces(str):
    return re.sub(r"\s+", "", str)

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
