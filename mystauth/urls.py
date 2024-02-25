from django.urls import path
from . import views


urlpatterns = [
    path('docs/', views.doc),
    path('terms/', views.terms),
    path('privacy/', views.privacy),
    path('auth/', views.originAuth),
    path('authorize/', views.oidcAuth),
    path('reset/', views.resetAuth),
    path('api/v1/user/register/get/', views.userRegOpts),
    path('api/v1/user/register/drop/', views.regDrop),
    path('api/v1/user/register/verify/', views.userRegister),
    path('api/v1/user/authenticate/get/', views.userAuthOpts),
    path('api/v1/user/authenticate/verify/', views.userAuthenticate),
    path('api/v1/user/reset/get/', views.resetRegOpts),
    path('api/v1/user/reset/verify/', views.resetRegister),
    path('api/v1/user/token/verify/', views.verifyToken),
    path('api/v1/origin/new/', views.newOriginAPI),
    path('api/v1/origin/edit/', views.editOrigin),
    path('api/v1/origin/cycle/', views.cycleAPI),
    path('api/v1/origin/delete/', views.delAPI),
    path('api/v1/user/delete/', views.delAccount),
    path('api/v1/user/reset/', views.newResetLink),
    path('.well-known/openid-configuration/', views.oidcConfig),
    path('api/v1/certs/', views.oidcSigningCerts),
]
