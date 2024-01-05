from django.urls import path
from . import views


urlpatterns = [
    path('docs/', views.doc),
    path('terms/', views.terms),
    path('privacy/', views.privacy),
    path('auth/', views.originAuth),
    path('api/v1/user/register/get/', views.userRegOpts),
    path('api/v1/user/register/verify/', views.userRegister),
    path('api/v1/user/authenticate/get/', views.userAuthOpts),
    path('api/v1/user/authenticate/verify/', views.userAuthenticate),
    path('api/v1/user/token/verify/', views.verifyToken),
    path('api/v1/origin/new/', views.newOriginAPI),
    path('api/v1/origin/edit/', views.editOrigin),
    path('api/v1/origin/cycle/', views.cycleAPI),
    path('api/v1/origin/delete/', views.delAPI),
    path('api/v1/user/delete/', views.delAccount),
]
