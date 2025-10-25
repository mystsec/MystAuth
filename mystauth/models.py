from django.db import models

# Create your models here.
class Auth(models.Model):
    user = models.TextField(editable=False)
    uid = models.TextField(editable=False) #unique
    credId = models.TextField(editable=False)
    pbk = models.TextField(editable=False)
    challenge = models.TextField(editable=False)
    signCount = models.PositiveBigIntegerField(default=0)
    oid = models.TextField(editable=False, default="None")
    timestamp = models.DateTimeField(auto_now=False, auto_now_add=True)
    fdata = models.TextField(null=True, editable=False)

class Origin(models.Model):
    oid = models.TextField() #unique
    uid = models.TextField(editable=False) #unique
    rid = models.TextField(editable=False, null=True) #unique
    uuid = models.TextField()
    salt = models.TextField()
    ttl = models.PositiveBigIntegerField(default=3600) #seconds
    bioOnly = models.BooleanField(default=False)
    allowReset = models.BooleanField(default=False)
    hashFct = models.PositiveBigIntegerField(default=1)
    userCount = models.PositiveBigIntegerField(default=0)
    apiTokens = models.PositiveBigIntegerField(default=100)
    restricted = models.BooleanField(default=False)
    #ips = jsonfield.JSONField(blank=True)

class Token(models.Model):
    oid = models.TextField(editable=False)
    user = models.TextField(editable=False)
    hash = models.TextField(editable=False)
    salt = models.TextField(editable=False, null=True)
    timestamp = models.DateTimeField(auto_now=False, auto_now_add=True)
    ttl = models.PositiveBigIntegerField(default=120) #seconds
    rst = models.BooleanField(default=False)
    nonce = models.TextField(null=True)
    key = models.TextField(null=True)
    fkey = models.TextField(null=True)
    edata = models.TextField(null=True)
