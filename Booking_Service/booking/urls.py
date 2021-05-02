from django.urls import path
from .views import create_or_all, canceled, about_one, all_hotels

urlpatterns = [
    path('', create_or_all),
    path('canceled', canceled),
    path('<str:booking_uid>', about_one),
    path('hotels', all_hotels),
]
