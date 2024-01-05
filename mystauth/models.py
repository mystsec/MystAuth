from django.db import models

# Create your models here.
class Auth(models.Model):
    user = models.TextField(editable=False)
    uid = models.TextField(editable=False) #unique
    credId = models.TextField(editable=False)
    pbk = models.TextField(editable=False)
    challenge = models.TextField()
    signCount = models.PositiveBigIntegerField(default=0)
    oid = models.TextField(editable=False, default="None")
    timestamp = models.DateTimeField(auto_now=False, auto_now_add=True)

class Origin(models.Model):
    oid = models.TextField() #unique
    uid = models.TextField(editable=False) #unique
    rid = models.TextField(editable=False, null=True) #unique
    uuid = models.TextField()
    salt = models.TextField()
    ttl = models.PositiveBigIntegerField(default=3600) #seconds
    bioOnly = models.BooleanField(default=False)
    userCount = models.PositiveBigIntegerField(default=0)
    apiTokens = models.PositiveBigIntegerField(default=100)
    #ips = jsonfield.JSONField(blank=True)

class Token(models.Model):
    oid = models.TextField(editable=False)
    user = models.TextField(editable=False)
    hash = models.TextField(editable=False)
    salt = models.TextField(editable=False, null=True)
    timestamp = models.DateTimeField(auto_now=False, auto_now_add=True)
    ttl = models.PositiveBigIntegerField(default=120) #seconds
