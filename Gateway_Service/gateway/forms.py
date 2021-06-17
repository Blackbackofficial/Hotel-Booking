from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.contrib.auth.models import User
from django.core import validators
# from .models import UserProfile, Question, Answer
from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
import re
import requests


class LoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

    # def clean(self):
    #     cleaned_data = super().clean()
    #     session = requests.get("http://localhost:8001/api/v1/session/login", cookies=request.COOKIES)
    #     try:
    #         User.objects.get(username=cleaned_data['username'])
    #     except ObjectDoesNotExist:
    #         raise forms.ValidationError("Не верный логин или пароль")
    #     return self.cleaned_data
    #
    # class Meta:
    #     model = User
    #     fields = ('username', 'password')


# class UserRegistrationForm(forms.Form):
#     first_name = forms.CharField(label='Имя', widget=forms.TextInput(attrs={'class': 'form-control'}))
#     last_name = forms.CharField(label='Фамилия', widget=forms.TextInput(attrs={'class': 'form-control'}))
#     username = forms.CharField(label='Логин', widget=forms.TextInput(attrs={'class': 'form-control'}))
#     email = forms.EmailField(label="E-mail", widget=forms.EmailInput(attrs={'class': 'form-control'}))
#     password = forms.CharField(label='Пароль', widget=forms.PasswordInput(attrs={'class': 'form-control'}))
#     password2 = forms.CharField(label='Повторите пароль', widget=forms.PasswordInput(attrs={'class': 'form-control'}))
#     avatar = forms.ImageField(label='Загрузите аватар', required=False)
#
#     class Meta:
#         model = UserProfile
#         fields = ('username', 'email', 'password', 'first_name', 'last_name')
#
#     def clean(self):
#         cleaned_data = super().clean()
#         if 'password' in cleaned_data and cleaned_data['password'] != cleaned_data['password2']:
#             raise forms.ValidationError("Пароли не совпадают")
#         if not cleaned_data['first_name'] or len(cleaned_data['first_name']) == 0:
#             raise forms.ValidationError("Невалидное ФИО")
#         if not cleaned_data['last_name'] or len(cleaned_data['last_name']) == 0:
#             raise forms.ValidationError("Невалидное ФИО")
#         if not cleaned_data['username'] or len(cleaned_data['username']) == 0 and not re.compile("^([A-Za-z0-9]+)+$")\
#                 .match(cleaned_data['username']):
#             raise forms.ValidationError("Невалидный логин")
#         if 'email' in cleaned_data and (not cleaned_data['email'] or len(cleaned_data['email']) == 0):
#             raise forms.ValidationError("Невалидный email")
#         return self.cleaned_data
#
#
# class AskForm(forms.Form):
#     title = forms.CharField(label='Титул', widget=forms.TextInput(
#         attrs={'class': 'form-control', 'placeholder': 'Суть вопроса'}))
#     text = forms.CharField(label='Текст', widget=forms.Textarea(
#         attrs={'class': 'form-control', 'placeholder': 'Подробнее о вопросе'}))
#     tags = forms.CharField(label='Теги', widget=forms.TextInput(
#         attrs={'class': 'form-control', 'placeholder': 'Указывайте через запятую'}))
#
#     class Meta:
#         model = Question
#         fields = ('title', 'tags')
#
#     def clean(self):
#         cleaned_data = super().clean()
#         if len(cleaned_data["title"]) > 30:
#             raise forms.ValidationError('Слишком длинный титутл вопроса')
#         if len(cleaned_data["text"]) > 255:
#             raise forms.ValidationError('Слишком длинное тело вопроса')
#         if len(cleaned_data["tags"]) >= 20:
#             raise forms.ValidationError('Слишком длинный тег')
#         return self.cleaned_data
#
#
# class AnswerForm(forms.Form):
#     text = forms.CharField(label='Ваш ответ:', widget=forms.Textarea(
#         attrs={'rows': 5, 'class': 'form-control', 'placeholder': 'Введите свой ответ'}))
#
#     class Meta:
#         model = Answer
#         fields = 'text'
#
#     def clean(self):
#         cleaned_data = super().clean()
#         if len(cleaned_data["text"]) > 255:
#             raise forms.ValidationError('Слишком длинный ответ')
#         return self.cleaned_data
#
