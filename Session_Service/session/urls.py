from django.urls import path
from .views import register, login, refresh, logout, verify, users

urlpatterns = [
    path('register', register),  #
    path('login', login),  #
    path('validate', verify),  #
    path('refresh', refresh),  #
    path('logout', logout),  #
    path('users', users),  #
]
