from django.shortcuts import render
from rest_framework.exceptions import AuthenticationFailed, ValidationError, ParseError
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from Gateway_Service.settings import JWT_KEY
from django.forms.models import model_to_dict
from django.core import serializers
from django.http import JsonResponse
from rest_framework import status
import requests
import json
import jwt

FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def login(request):
    """
    POST: {
          "username": "qwerty",
          "password": "qwerty"
          }
    """
    session = requests.post("http://localhost:8001/api/v1/session/login",
                            json={"username": request.data["username"], "password": request.data["password"]})
    if session.status_code != 200:
        return JsonResponse(session.json(), status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse({'success': 'logined'}, status=status.HTTP_200_OK)
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def register(request):
    """
    POST: {
          "role": "admin", вставляется только при админке или "user"
          "username": "qwerty",
          "name": "Ivan",
          "email": "Chenov-Ivan.1997@yandex.ru",
          "password": "qwerty"
          }
    """
    session = requests.post("http://localhost:8001/api/v1/session/register", json=request.data)
    if session.status_code != 200:
        return JsonResponse(session.json(), status=status.HTTP_400_BAD_REQUEST)
    return JsonResponse({'success': 'register'}, status=status.HTTP_200_OK)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def logout(request):
    """
    POST: in the post only JWT
    """
    session = requests.post("http://localhost:8001/api/v1/session/logout", cookies=request.COOKIES)
    if session.status_code != 200:
        return JsonResponse(session.json(), status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse({'success': 'logout'}, status=status.HTTP_200_OK)
    response.delete_cookie('jwt')
    return response




