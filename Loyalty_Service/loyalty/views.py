from rest_framework.exceptions import AuthenticationFailed
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from django.http import JsonResponse
from .models import UserLoyalty
from Loyalty_Service.settings import JWT_KEY
from .serializers import LoyaltySerializer
from rest_framework import status
import jwt

FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def create(request):
    """
    POST: {
          "user_uid": "b5f342ce-2419-4a17-8800-b921e90b5fbf"
          }
    """
    try:
        data = {"user_uid": request.data["user_uid"], "status_loyalty": "None", "discount": "0", "balance": "50000"}
        serializer = LoyaltySerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return JsonResponse(serializer.data)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def balance(request):
    try:
        data = auth(request)
        userLoyalty = UserLoyalty.objects.filter(user_uid=data['user_uid']).first()
        serializer = LoyaltySerializer(userLoyalty)
        return JsonResponse(serializer.data)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['PATCH'])
def edit(request):
    """
    BRONZE: 7%
    SILVER: 15%
    GOLD: 25%
    request: { "active": "UP" } or { "active": "DOWN" }
    """
    status_list = {'None': 0, "BRONZE": 5, "SILVER": 12, "GOLD": 17}
    status_key = list(status_list.keys())
    data = auth(request)
    userLoyalty = UserLoyalty.objects.get(user_uid=data['user_uid'])
    i = 0

    while i < len(status_key):
        if status_key[i] == userLoyalty.status:
            break
        i += 1

    if request.data['active'] == 'UP':
        if i < len(status_key) - 1:
            i += 1
    elif request.data['active'] == 'DOWN':
        if i > 0:
            i -= 1
    userLoyalty.status = status_key[i]
    userLoyalty.discount = status_list[status_key[i]]

    userLoyalty.save()
    return JsonResponse({'detail': 'success edit'}, status=status.HTTP_200_OK)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['DELETE'])
def delete(request):
    try:
        data = auth(request)
        userLoyalty = UserLoyalty.objects.get(user_uid=data['user_uid'])
        userLoyalty.delete()
        return JsonResponse({'detail': 'success deleted'}, status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def balance_static(request, user_uid):
    try:
        auth(request)
        userLoyalty = UserLoyalty.objects.get(user_uid=user_uid)
        serializer = LoyaltySerializer(userLoyalty)
        return JsonResponse(serializer.data)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['PATCH'])
def edit_balance(request):
    try:
        user = auth(request)
        userLoyalty = UserLoyalty.objects.get(user_uid=user['user_uid'])
        if request.data['status'] == "PAID":
            userLoyalty.balance = userLoyalty.balance - int(request.data['price'])
            if userLoyalty.balance < 0:
                return JsonResponse({'message': '{}'.format(Exception)}, status=status.HTTP_400_BAD_REQUEST)
        elif request.data['status'] == "REVERSED":
            userLoyalty.balance = userLoyalty.balance + int(request.data['price'])

        userLoyalty.save()
        return JsonResponse({'detail': 'success edit'}, status=status.HTTP_200_OK)
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
