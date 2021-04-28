from django.urls import path
from .views import about_loyalty, create_loyalty, edit_loyalty, delete_loyalty

urlpatterns = [
    path('balance/', about_loyalty),  # Посмотреть баланс бонусной программы
    path('create/', create_loyalty),  # Создание при регистрации
    path('edit-loyalty/', edit_loyalty),  # Понизить/повысить лояльность
    path('delete/', delete_loyalty),  # При удаления пользователя
]
