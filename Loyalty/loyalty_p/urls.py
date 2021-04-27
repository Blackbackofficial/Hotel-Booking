from django.urls import path
from Loyalty.loyalty_p.views import about_loyalty, up_loyalty, down_loyalty

urlpatterns = [
    path('loyalty', about_loyalty),  # Посмотреть баланс бонусной программы
    path('loyalty', up_loyalty), # Повысить лояльность
    path('loyalty', down_loyalty), # Понизить лояльность
]