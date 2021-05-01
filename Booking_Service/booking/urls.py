from django.urls import path
from .views import create_or_all, canceled, about_one, all_hotels

urlpatterns = [
    path('', create_or_all),  # Создание при регистрации
    path('canceled', canceled),  # Понизить/повысить лояльность
    path('<str:booking_uid>', about_one),  # Посмотреть баланс бонусной программы
    path('hotels', all_hotels),  # При удаления пользователя
]
