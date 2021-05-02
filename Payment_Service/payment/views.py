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
@api_view(['POST'])
def create(request):
    try:
        data = auth(request)
        loyBalance = requests.get("http://localhost:8000/api/v1/loyalty/balance", cookies=request.COOKIES)
        if loyBalance.status_code != 200:
            return JsonResponse({'error': 'Error in loyalty'}, status=status.HTTP_400_BAD_REQUEST)
        loyBalance = loyBalance.json()
        if loyBalance['discount'] is None:
            loyBalance['discount'] = 0
        data.update({'status': 'NEW', 'price': request.data["price"]/100*(100-loyBalance['discount'])})
        serializer = PaymentSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return JsonResponse(serializer.data)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def pay(request, payment_uid):
    try:
        auth(request)
        payment = Payment.objects.get(payment_uid=payment_uid)
        payment.status = "PAID"
        payment.save()
        return JsonResponse({'detail': 'PAID'}, status=status.HTTP_200_OK)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def reversed(request, payment_uid):
    try:
        auth(request)
        payment = Payment.objects.get(payment_uid=payment_uid)
        payment.status = "REVERSED"
        payment.save()
        return JsonResponse({'detail': 'REVERSED'}, status=status.HTTP_200_OK)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def close(request, payment_uid):
    try:
        auth(request)
        payment = Payment.objects.get(payment_uid=payment_uid)
        payment.status = "CANCELED"
        payment.save()
        return JsonResponse({'detail': 'CANCELED'}, status=status.HTTP_200_OK)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def status_pay(request, payment_uid):
    try:
        auth(request)
        payment = Payment.objects.get(payment_uid=payment_uid)
        serializer = PaymentSerializer(payment)
        return JsonResponse(serializer.data)
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
