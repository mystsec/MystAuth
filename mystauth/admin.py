from django.contrib import admin
from .models import Origin, Auth

# Register your models here.
class OriginAdmin(admin.ModelAdmin):
    list_display = ['oid', 'rid', 'ttl', 'bioOnly', 'userCount', 'apiTokens']
admin.site.register(Origin, OriginAdmin)

class AuthAdmin(admin.ModelAdmin):
    list_display = ['user', 'oid', 'timestamp']
admin.site.register(Auth, AuthAdmin)
