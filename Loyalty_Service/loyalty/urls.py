from django.urls import path
from .views import balance, create, edit, delete, balance_static

urlpatterns = [
    path('create', create),  # Создание при регистрации  #
    path('edit', edit),  # Понизить/повысить лояльность  #
    path('balance', balance),  # Посмотреть баланс бонусной программы  #
    path('delete', delete),  # При удалении пользователя
    path('status/<str:user_uid>', balance_static),  # кошелёк пользователя
]
