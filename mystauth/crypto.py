from .models import Auth, Origin, Token
import secrets
import hashlib
import fastpbkdf2
import argon2
import base64
import uuid
import datetime
import pytz

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

#Generate Hash Materials
def getHashMat():
    return {'uuid': secrets.token_hex(64), 'salt': secrets.token_bytes(64)}


#Checks Token Validity
def validateToken(oid, usr, key, erst=False, nrst=False):
    if len(str(key)) > 400:
        return {'auth_check': False, 'time_check': None, 'token': token}
    token = Token.objects.get(user=usr, oid=oid)
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


#Authenticates Auth Token
def authenticateToken(oid, usr, key, ottl, erst=False, nrst=False):
    try:
        auth = validateToken(oid, usr, key, erst, nrst)
        token = auth['token']
        if auth['auth_check']:
            if auth['time_check']:
                token.delete()
                newToken = generateToken(oid, usr, ottl, nrst)
                return {'success': True, 'token': newToken}
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


#Generate Auth Token
def generateToken(oid, usr, ttl=120, rst=False):
    Token.objects.filter(user=usr, oid=oid).delete()
    hashMat = getHashMat()
    hash = HASH(hashMat["salt"], hashMat["uuid"])
    token = Token(oid=oid, user=usr, hash=hash, salt=hashMat["salt"], ttl=ttl, rst=rst)
    token.save()
    return hashMat["uuid"]


#Generates New Origin
def newOrigin(oid, ttl=3600, bio_only=False, hash=1):
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
    auth = Origin(uid = uid, uuid = hash, salt = hashMat["salt"], rid = rid, oid = oid, ttl = ttl, bioOnly = bio_only, hashFct = hash)
    auth.save()
    result = {'success': True, 'id': uid, 'apiKey': hashMat["uuid"], 'reqId': rid}
    return result


#Helper Functions
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
