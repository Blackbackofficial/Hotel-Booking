from django.urls import path
from .views import create, pay, reversed, close, status_pay

urlpatterns = [
    path('create', create),  #
    path('pay/<str:payment_uid>', pay),  #
    path('reversed/<str:payment_uid>', reversed),  #
    path('close/<str:payment_uid>', close),  #
    path('status/<str:payment_uid>', status_pay),  #
]
