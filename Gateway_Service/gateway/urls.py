from django.urls import path
from .views import login, register, logout, users, add_hotel, all_hotels, one_hotel_or_delete, create_booking_or_all

urlpatterns = [
    path('login', login),  #
    path('register', register),  #
    path('logout', logout),  #
    path('users', users),  #
    path('hotel', add_hotel),  #
    path('hotels', all_hotels),  #
    path('hotels/<str:hotel_uid>', one_hotel_or_delete),  #
    path('booking', create_booking_or_all) #
]
