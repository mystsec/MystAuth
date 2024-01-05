from django.db import models

# Create your models here.
class Acc(models.Model):
    user = models.TextField(editable=False)
    oid = models.TextField()
