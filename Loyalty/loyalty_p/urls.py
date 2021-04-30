from django.urls import path
from .views import about, create, edit, delete

urlpatterns = [
    path('create', create),  # Создание при регистрации
    path('edit-loyalty', edit),  # Понизить/повысить лояльность
    path('balance', about),  # Посмотреть баланс бонусной программы
    path('delete', delete),  # При удаления пользователя
]
