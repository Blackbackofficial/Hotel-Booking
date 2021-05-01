from django.urls import path
from .views import register, login, refresh, logout, validate, users

urlpatterns = [
    path('register', register),
    path('login', login),
    path('validate', validate),
    path('refresh', refresh),
    path('logout', logout),
    path('users', users),
]
