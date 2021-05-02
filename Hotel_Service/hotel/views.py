from rest_framework.exceptions import AuthenticationFailed, ValidationError, ParseError
from django.shortcuts import render
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from Payment_Service.settings import JWT_KEY
from .serializers import PaymentSerializer
from django.http import JsonResponse
from rest_framework import status
from .models import Payment
import requests
import jwt

FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET', 'DELETE'])
def about_or_delete(request, booking_uid):
    try:
        auth(request)
        payment_uid = Reservations.objects.get(booking_uid=booking_uid).payment_uid
        payStatus = requests.post("http://localhost:8002/api/v1/payment/close/{}".format(payment_uid),
                                  cookies=request.COOKIES)
        if payStatus.status_code == 200:
            return JsonResponse(payStatus.json(), status=status.HTTP_200_OK)
        return JsonResponse({'detail': 'NOT CANCELED'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET', 'PATCH'])
def all_hotels_or_add_hotel(request, booking_uid):
    try:
        auth(request)
        payment_uid = Reservations.objects.get(booking_uid=booking_uid).payment_uid
        payStatus = requests.post("http://localhost:8002/api/v1/payment/close/{}".format(payment_uid),
                                  cookies=request.COOKIES)
        if payStatus.status_code == 200:
            return JsonResponse(payStatus.json(), status=status.HTTP_200_OK)
        return JsonResponse({'detail': 'NOT CANCELED'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def change_rooms(request, booking_uid):
    try:
        auth(request)
        payment_uid = Reservations.objects.get(booking_uid=booking_uid).payment_uid
        payStatus = requests.post("http://localhost:8002/api/v1/payment/close/{}".format(payment_uid),
                                  cookies=request.COOKIES)
        if payStatus.status_code == 200:
            return JsonResponse(payStatus.json(), status=status.HTTP_200_OK)
        return JsonResponse({'detail': 'NOT CANCELED'}, status=status.HTTP_400_BAD_REQUEST)
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
