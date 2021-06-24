from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.contrib.auth.models import User
from django.core import validators
from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
import re
import requests


class LoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))


class UserRegistrationForm(forms.Form):
    first_name = forms.CharField(label='Имя', widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(label='Фамилия', widget=forms.TextInput(attrs={'class': 'form-control'}))
    username = forms.CharField(label='Логин', widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(label="E-mail", widget=forms.EmailInput(attrs={'class': 'form-control'}))
    password = forms.CharField(label='Пароль', widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    password2 = forms.CharField(label='Повторите пароль', widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    avatar = forms.ImageField(label='Аватар:', widget=forms.FileInput(attrs={'class': 'form-control'}), required=False)


class NewHotel(forms.Form):
    title = forms.CharField(label='Название:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    short_text = forms.CharField(label='Описание:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    rooms = forms.IntegerField(label='Количество комнат:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    cities = forms.CharField(label='Город:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    location = forms.CharField(label='Адрес:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    cost = forms.IntegerField(label="Стоимость номера:", widget=forms.TextInput(attrs={'class': 'form-control'}))
    photo = forms.ImageField(label='Фото отеля:', widget=forms.FileInput(attrs={'class': 'form-control'}), required=False)


class DeleteHotel(forms.Form):
    hotel_uid = forms.CharField(label='Hotel UUID:', widget=forms.TextInput(attrs={'class': 'form-control'}))
