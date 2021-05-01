from rest_framework.exceptions import AuthenticationFailed
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from django.http import JsonResponse
from .models import UserLoyalty
from Booking_Service.settings import JWT_KEY
from .serializers import BookingSerializer
from rest_framework import status
import requests
import jwt

FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST', 'GET'])
def create_or_all(request):
    try:
        data = auth(request)

    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['DELETE'])
def canceled(request, booking_uid):
    try:
        data = auth(request)

    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def about_one(request, booking_uid):
    try:
        data = auth(request)

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
