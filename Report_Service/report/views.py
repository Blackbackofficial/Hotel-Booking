from rest_framework.exceptions import AuthenticationFailed
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from django.http import JsonResponse
from .models import UserLoyalty
from Loyalty_Service.settings import JWT_KEY
from .serializers import LoyaltySerializer
from rest_framework import status
import requests
import jwt

FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def report_by_users(request):
    """
    POST: {
          "user_uid": "b5f342ce-2419-4a17-8800-b921e90b5fbf"
          }
    """
    try:
        data = {"user_uid": request.data["user_uid"], "status": "None", "discount": "0"}
        serializer = LoyaltySerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return JsonResponse(serializer.data)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def report_by_hotels(request):
    """
    POST: {
          "user_uid": "b5f342ce-2419-4a17-8800-b921e90b5fbf"
          }
    """
    try:
        data = {"user_uid": request.data["user_uid"], "status": "None", "discount": "0"}
        serializer = LoyaltySerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return JsonResponse(serializer.data)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)