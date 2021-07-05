from django.urls import path
from .views import add_hotlike, show_hotlikes, delete_hotel, create_hotel, create_comment, add_comlike, show_comlikes, \
    delete_comment, load_comments, load_hotlikes, delete_all_comments, update_comment
urlpatterns = [
    path('create_comment', create_comment),  #
    path('add_comlike', add_comlike),  #
    path('show_comlikes', show_comlikes),  #
    path('update_comment', update_comment),  #
    path('delete_comment', delete_comment),  #
    path('delete_all_comments', delete_all_comments),  #
    path('load_comments', load_comments),  #
    path('create_hotel', create_hotel),  #
    path('add_hotlike', add_hotlike),  #
    path('show_hotlikes', show_hotlikes),  #
    path('delete_hotel', delete_hotel),  #
    path('load_hotlikes', load_hotlikes),  #
]