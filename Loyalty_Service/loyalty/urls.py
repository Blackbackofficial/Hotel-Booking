from django.urls import path
from .views import balance, create, edit, delete, balance_static, edit_balance

urlpatterns = [
    path('create', create),  # Создание при регистрации  #
    path('edit', edit),  # Понизить/повысить лояльность  #
    path('balance', balance),  # Посмотреть баланс бонусной программы  #
    path('delete', delete),  # При удалении пользователя
    path('edit_balance', edit_balance),  # Меняем баланс при оплате
    path('status/<str:user_uid>', balance_static),  # кошелёк пользователя
]
