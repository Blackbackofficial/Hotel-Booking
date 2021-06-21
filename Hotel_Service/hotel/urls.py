from django.urls import path
from .views import about_or_delete, all_hotels_or_add_hotel, change_rooms, cities, filter_date

urlpatterns = [
    path('cities', cities),  #
    path('date', filter_date),
    path('<str:hotel_uid>', about_or_delete),  #
    path('', all_hotels_or_add_hotel),  #
    path('<str:hotel_uid>/rooms', change_rooms),
]
