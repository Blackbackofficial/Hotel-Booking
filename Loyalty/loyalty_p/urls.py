from django.urls import path
from .views import about_loyalty, up_loyalty, down_loyalty

urlpatterns = [
    path('loyalty/', about_loyalty),  # Посмотреть баланс бонусной программы
    path('up-loyalty/', up_loyalty),  # Повысить лояльность
    path('down-loyalty/', down_loyalty),  # Понизить лояльность
]