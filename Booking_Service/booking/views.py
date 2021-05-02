from rest_framework.exceptions import AuthenticationFailed
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from django.http import JsonResponse
from .models import Reservations
from django.core import serializers
from Booking_Service.settings import JWT_KEY
from .serializers import BookingSerializer
from django.forms.models import model_to_dict
from rest_framework import status
import requests
import json
import jwt

FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST', 'GET'])
def create_or_all(request):
    """
    POST: { "hotel_uid": "5c325464-7445-4147-bd2d-1598641d2248",
            "date_start": "2013-03-30",
            "date_end": "2021-07-17",
            "comment": "somebody",
            "price": 20000
          }
    """
    try:
        data = auth(request)
        if request.method == 'POST':
            payBalance = requests.post("http://localhost:8002/api/v1/payment/create",
                                       json={"price": request.data["price"]},
                                       cookies=request.COOKIES)
            if payBalance.status_code != 200:
                return JsonResponse({'error': 'Error in payment'}, status=status.HTTP_400_BAD_REQUEST)
            payBalance = payBalance.json()
            if "comment" not in request.data:
                request.data.update({"comment": ""})
            new_reservation = {"hotel_uid": request.data["hotel_uid"], "user_uid": data["user_uid"],
                               "payment_uid": payBalance["payment_uid"], "date_start": request.data["date_start"],
                               "date_end": request.data["date_end"], 'comment': request.data["comment"]}
            serializer = BookingSerializer(data=new_reservation)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            reservations = model_to_dict(Reservations.objects.latest('id'))
            return JsonResponse(reservations, status=status.HTTP_200_OK, safe=False)
        elif request.method == 'GET':
            reservations = Reservations.objects.filter(user_uid=data["user_uid"])
            users_reservations = json.loads(serializers.serialize('json', reservations))
            return JsonResponse(users_reservations, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['DELETE'])
def canceled(request, booking_uid):
    try:
        data = auth(request)
        payBalance = requests.post("http://localhost:8002/api/v1/payment/create",
                                   json={"price": request.data["price"]},
                                   cookies=request.COOKIES)
        # завтра подумаю

    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def about_one(request, booking_uid):
    try:
        auth(request)
        reservations = Reservations.objects.get(booking_uid=booking_uid)
        reservations = model_to_dict(reservations)
        hotel = requests.get("http://localhost:8002/api/v1/hotel/status/{}".format(reservations["hotel_uid"]),
                             cookies=request.COOKIES)
        if hotel.status_code == 200:
            hotel = hotel.json()
            reservations.update(hotel)
        payBalance = requests.get("http://localhost:8002/api/v1/payment/status/{}".format(reservations["payment_uid"]),
                                  cookies=request.COOKIES)
        if payBalance.status_code == 200:
            payBalance = payBalance.json()
            reservations.update(payBalance)
        return JsonResponse(reservations, status=status.HTTP_200_OK)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def all_hotels(request):  # only user 'admin'
    try:
        data = auth(request)

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
