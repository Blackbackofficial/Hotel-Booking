from django.urls import path
from .views import report_by_booking, report_by_hotels

urlpatterns = [
    path('booking', report_by_booking),  # Отчет по пользователям
    path('hotels-filling', report_by_hotels),  # Отчет по отелям
]
