from django.urls import path
from .views import create_or_all, canceled, about_one, all_hotels, pay, reversed, all_hotels_statics, filter_booking

urlpatterns = [
    path('', create_or_all),  #
    path('canceled/<str:booking_uid>', canceled),
    path('date/<str:date_start>/<str:date_end>', filter_booking),
    path('static', all_hotels_statics),  # only admin
    path('pay/<str:booking_uid>', pay),
    path('reversed/<str:booking_uid>', reversed),
    path('<str:booking_uid>', about_one),  #
    path('hotels/<str:hotel_uid>', all_hotels),  # only admin
]
