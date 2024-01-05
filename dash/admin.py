from django.contrib import admin
from .models import Acc

# Register your models here.
class AccAdmin(admin.ModelAdmin):
    list_display = ['user', 'oid']
admin.site.register(Acc, AccAdmin)
