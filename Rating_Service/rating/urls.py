from django.urls import path
from .views import add_hotlike, show_hotlikes, delete_hotel, create_hotel, create_comment, add_comlike, show_comlikes, \
    delete_comment, load_comments, load_hotlikes, all_comments
urlpatterns = [
    path('create_comment', create_comment),  #
    path('all_comments', all_comments),  #
    path('add_comlike', add_comlike),  #
    path('show_comlikes', show_comlikes),  #
    path('delete_comment', delete_comment),  #
    path('load_comments', load_comments),  #
    path('create_hotel', create_hotel),  #
    path('add_hotlike', add_hotlike),  #
    path('show_hotlikes', show_hotlikes),  #
    path('delete_hotel', delete_hotel),  #
    path('load_hotlikes', load_hotlikes),  #
]