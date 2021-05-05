from django.shortcuts import render
from rest_framework.exceptions import AuthenticationFailed
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


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def users(request):
    """
    GET: use JWT
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    users = requests.get("http://localhost:8001/api/v1/session/users", cookies=session.cookies)
    if users.status_code != 200:
        return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse(users.json(), status=status.HTTP_200_OK, safe=False)
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def add_hotel(request):
    """
    POST: {
          "title": "The Royal Hotel",
          "short_text": "По утрам гостям подают американский завтрак.",
          "rooms": "300",
          "location": "Leninskiy Prospekt 95, Москва, Россия"
          } only admin
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    hotel = requests.post("http://localhost:8004/api/v1/hotels", json=request.data, cookies=session.cookies)
    if hotel.status_code != 200:
        return JsonResponse(hotel.json(), status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse(hotel.json(), status=status.HTTP_200_OK, safe=False)
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def all_hotels(request):
    """
    GET: use JWT
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    hotel = requests.get("http://localhost:8004/api/v1/hotels", json=request.data, cookies=session.cookies)
    if hotel.status_code != 200:
        return JsonResponse(hotel.json(), status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse(hotel.json(), status=status.HTTP_200_OK, safe=False)
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET', 'DELETE'])
def one_hotel_or_delete(request, hotel_uid):
    """
    GET, DELETE: use JWT & hotel_uid
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        hotel = requests.get("http://localhost:8004/api/v1/hotels/{}"
                             .format(hotel_uid), json=request.data, cookies=session.cookies)
        response = JsonResponse(hotel.json(), status=status.HTTP_200_OK, safe=False)
    else:  # DELETE
        hotel = requests.delete("http://localhost:8004/api/v1/hotels/{}"
                                .format(hotel_uid), json=request.data, cookies=session.cookies)
        response = JsonResponse({'detail': 'success deleted'}, status=status.HTTP_204_NO_CONTENT, safe=False)
    if hotel.status_code != 200 and hotel.status_code != 204:
        return JsonResponse(hotel.json(), status=status.HTTP_400_BAD_REQUEST)
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response

