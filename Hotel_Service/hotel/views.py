from rest_framework.exceptions import AuthenticationFailed, ValidationError, ParseError
from django.shortcuts import render
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from Hotel_Service.settings import JWT_KEY
from .serializers import HotelsSerializer
from django.forms.models import model_to_dict
from django.core import serializers
from django.http import JsonResponse
from rest_framework import status
from .models import Hotels
import requests
import json
import jwt

FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET', 'DELETE'])
def about_or_delete(request, hotel_uid):
    try:
        data = auth(request)
        if request.method == 'GET':
            hotels = Hotels.objects.filter(hotel_uid=hotel_uid)
            if len(hotels) == 0:
                return JsonResponse({'error': 'No content'}, status=status.HTTP_400_BAD_REQUEST)
            hotels = json.loads(serializers.serialize('json', hotels))
            return JsonResponse(hotels[0]['fields'], status=status.HTTP_200_OK, safe=False)
        else:  # DELETE only admin
            if 'admin' not in data['role']:
                return JsonResponse({'detail': 'You are not admin!'}, status=status.HTTP_400_BAD_REQUEST)
            hotel = Hotels.objects.get(hotel_uid=hotel_uid)
            hotel.delete()
            return JsonResponse({'detail': 'success deleted'}, status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET', 'POST'])
def all_hotels_or_add_hotel(request):
    """
    POST: {
          "title": "some text",
          "short_text": "another some text",
          "rooms": 300,
          "location": "Moscow, Leninski prospekt 49/2",
          "cost": 3992
          } only admin
    """
    try:
        data = auth(request)
        if request.method == 'GET':
            hotels = Hotels.objects.all()
            hotels = json.loads(serializers.serialize('json', hotels))
            for hotel in hotels:
                fields = hotel["fields"]
                hotel.clear()
                hotel.update(fields)
            return JsonResponse(hotels, status=status.HTTP_200_OK, safe=False)
        elif request.method == 'POST':  # only admin
            if 'admin' not in data['role']:
                return JsonResponse({'detail': 'You are not admin!'}, status=status.HTTP_400_BAD_REQUEST)
            new_hotel = {"title": request.data["title"], "short_text": request.data["short_text"],
                         "rooms": request.data["rooms"], "location": request.data["location"], "cost": request.data["cost"]}
            serializer = HotelsSerializer(data=new_hotel)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            hotel = model_to_dict(Hotels.objects.latest('id'))
            hotel.pop('photo')  # временно
            return JsonResponse(hotel, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['PATCH'])
def change_rooms(request, hotel_uid):
    """
    PATCH: {
            "reservation": "Done" or "reservation": "Canceled"
           }
    """
    try:
        auth(request)
        hotel = Hotels.objects.get(hotel_uid=hotel_uid)
        if request.data["reservation"] == "Canceled":
            if hotel.rooms > 0:
                hotel.rooms += 1
        elif request.data["reservation"] == "Done":
            if hotel.rooms > 0:
                hotel.rooms -= 1
        else:
            return JsonResponse({"detail": "Validation error in 'reservation'"}, status=status.HTTP_400_BAD_REQUEST)

        hotel.save()
        return JsonResponse({'rooms': '{}'.format(hotel.rooms)}, status=status.HTTP_200_OK)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


# subsidiary
def auth(request):
    token = request.COOKIES.get('jwt')

    if not token:
        raise AuthenticationFailed('Unauthenticated!')

    payload = jwt.decode(token, JWT_KEY, algorithms=['HS256'], options={"verify_exp": False})
    payload.pop('exp')
    payload.pop('iat')
    return payload
