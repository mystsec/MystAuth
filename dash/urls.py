from django.urls import path
from . import views

urlpatterns = [
    path('', views.dash),
    path('signout/', views.signout),
]
