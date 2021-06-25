from django.urls import path
from .views import login, register, logout, users, add_hotel, all_hotels, one_hotel_or_delete, create_booking_or_all, \
    one_booking, all_booking_hotels, pay_booking, close_booking, report_booking, report_user, report_hotels, cities

urlpatterns = [
    # API
    path('login', login),  #
    path('register', register),  #
    path('logout', logout),  #
    path('users', users),  #
    path('hotel', add_hotel),  #
    path('hotels', all_hotels),  #
    path('hotels/<str:hotel_uid>', one_hotel_or_delete),  #
    path('booking', create_booking_or_all),  #
    path('booking/<str:booking_uid>', one_booking),  #
    path('booking/hotels/<str:hotel_uid>', all_booking_hotels),  #
    path('booking/<str:booking_uid>/pay', pay_booking),  #
    path('booking/<str:booking_uid>/close', close_booking),  #
    path('reports/booking', report_booking),  #
    path('reports/users', report_user),  #
    path('reports/hotels-filling', report_hotels),  #
    path('cities', cities)
]
