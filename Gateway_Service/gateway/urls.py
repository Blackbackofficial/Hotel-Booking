from django.urls import path
from .views import login, register, logout, users, add_hotel, all_hotels, one_hotel_or_delete

urlpatterns = [
    path('login', login),  #
    path('register', register),  #
    path('logout', logout),  #
    path('users', users),  #
    path('hotel/add', add_hotel),  #
    path('hotels', all_hotels),  #
    path('hotels/<str:hotel_uid>', one_hotel_or_delete),  #
]
