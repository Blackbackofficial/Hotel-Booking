from django.urls import path
from .views import create, pay, reversed, close, status

urlpatterns = [
    path('create', create),
    path('pay', pay),
    path('reversed', reversed),
    path('close', close),
    path('status/{<str:payment_uid>', logout),
]