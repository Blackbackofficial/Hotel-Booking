from django.urls import path
from .views import report_by_booking, report_by_hotels, report_by_users

urlpatterns = [
    path('booking', report_by_booking),  # Отчет по бронированию
    path('users', report_by_users),  # Отчет по пользователям
    path('hotels-filling', report_by_hotels),  # Отчет по отелям
]
