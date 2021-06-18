from django.urls import path
from .views import index, make_login, make_logout, registration, balance, add_hotel_admin, admin, delete_hotel_admin

urlpatterns = [
    # VIEW
    path('index', index, name="index"),
    path('login', make_login, name="login"),
    path('logout', make_logout, name="logout"),
    path('signup', registration, name="signup"),
    path('balance', balance, name="balance"),
    path('add-hotel', add_hotel_admin, name="add_hotel"),
    path('admin', admin, name="admin"),
    path('delete-hotel', delete_hotel_admin, name="delete_hotel"),
]
