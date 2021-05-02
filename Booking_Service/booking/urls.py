from django.urls import path
from .views import create_or_all, canceled, about_one, all_hotels

urlpatterns = [
    path('', create_or_all),
    # path('canceled/<str:booking_uid>', canceled),
    # path('pay/<str:booking_uid>', canceled),
    # path('reversed/<str:booking_uid>', canceled),
    path('<str:booking_uid>', about_one),
    path('hotels/<str:hotel_uid>', all_hotels),
]
