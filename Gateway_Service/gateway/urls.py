from django.urls import path
from .views import login, register, logout, users

urlpatterns = [
    path('login', login),  #
    path('register', register),  #
    path('logout', logout),  #
    path('users', users)  #
]
