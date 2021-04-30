from rest_framework.exceptions import AuthenticationFailed, ValidationError, ParseError
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from rest_framework.parsers import JSONParser
from django.http import JsonResponse
from .models import UserLoyalty
from Loyalty.settings import JWT_KEY
from .serializers import LoyaltySerializer
from rest_framework import status
import jwt
import uuid

FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def create(request):
    try:
        data = auth(request)
        data.update({'user_uid': data['user_uid'], 'status': 'BRONZE', 'discount': '0'})
        serializer = LoyaltySerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def about(request):
    i = 1


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['PATCH'])
def edit(request):
    i = 1


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['DELETE'])
def delete(request):
    i = 1


# subsidiary
def auth(request):
    token = request.COOKIES.get('jwt')

    if not token:
        raise AuthenticationFailed('Unauthenticated!')

    payload = jwt.decode(token, JWT_KEY, algorithms=['HS256'], options={"verify_exp": False})
    payload.pop('exp')
    payload.pop('iat')
    return payload
