from django.urls import path
from .views import login, register, logout

urlpatterns = [
    path('login', login),
    path('register', register),
    path('logout', logout),
]
