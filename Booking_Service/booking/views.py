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
from datetime import datetime as dt
import requests
import datetime
import json
import jwt
import pytz

FAILURES = 3
TIMEOUT = 6

# Time zone
tz_MOS = pytz.timezone('Europe/Moscow')


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
            new_reservation.update({"date_create": dt.now(tz_MOS).strftime('%Y-%m-%d %H:%M:%S %Z%z')})
            return JsonResponse(new_reservation, status=status.HTTP_200_OK, safe=False)
        elif request.method == 'GET':
            reservations = Reservations.objects.filter(user_uid=data["user_uid"])
            users_reservations = json.loads(serializers.serialize('json', reservations))
            for res in users_reservations:
                payBalance = requests.get(
                    "http://localhost:8002/api/v1/payment/status/{}".format(res['fields'].get("payment_uid")),
                    cookies=request.COOKIES)
                if payBalance.status_code == 200:
                    payBalance = payBalance.json()
                    res['fields'].update(payBalance)
                hotel = requests.get(
                    "http://localhost:8002/api/v1/hotel/status/{}".format(res['fields'].get("hotel_uid")),
                    cookies=request.COOKIES)
                if hotel.status_code == 200:
                    hotel = hotel.json()
                    res['fields'].update(hotel)
                fields = res["fields"]
                res.clear()
                res.update(fields)
            return JsonResponse(users_reservations, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['DELETE'])
def canceled(request, booking_uid):
    try:
        auth(request)
        payment_uid = Reservations.objects.get(booking_uid=booking_uid).payment_uid
        payStatus = requests.delete("http://localhost:8002/api/v1/payment/close/{}".format(payment_uid),
                                    cookies=request.COOKIES)
        if payStatus.status_code == 200:
            return JsonResponse(payStatus.json(), status=status.HTTP_200_OK)
        return JsonResponse({'detail': 'NOT CANCELED'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def pay(request, booking_uid):
    try:
        auth(request)
        payment_uid = Reservations.objects.get(booking_uid=booking_uid).payment_uid
        payStatus = requests.post("http://localhost:8002/api/v1/payment/pay/{}".format(payment_uid),
                                  cookies=request.COOKIES)
        if payStatus.status_code == 200:
            return JsonResponse(payStatus.json(), status=status.HTTP_200_OK)
        return JsonResponse({'detail': 'NOT PAID'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def reversed(request, booking_uid):
    try:
        auth(request)
        payment_uid = Reservations.objects.get(booking_uid=booking_uid).payment_uid
        payStatus = requests.post("http://localhost:8002/api/v1/payment/reversed/{}".format(payment_uid),
                                  cookies=request.COOKIES)
        if payStatus.status_code == 200:
            return JsonResponse(payStatus.json(), status=status.HTTP_200_OK)
        return JsonResponse({'detail': 'NOT REVERSED'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def about_one(request, booking_uid):
    try:
        auth(request)
        reservations = Reservations.objects.get(booking_uid=booking_uid)
        reservations = model_to_dict(reservations)
        hotel = requests.get("http://localhost:8002/api/v1/hotel/status/{}".format(reservations["hotel_uid"]),
                             cookies=request.COOKIES)  # нужно доделать
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
@api_view(['GET'])
def filter_booking(request, date_start, date_end):
    try:
        reservations = list(Reservations.objects.filter(date_start__gte=date_start, date_end__lte=date_end).values())
        if len(reservations) == 0:
            return JsonResponse({'message': 'No content'}, status=status.HTTP_204_NO_CONTENT)
        for res in reservations:
            payBalance = requests.get(
                "http://localhost:8002/api/v1/payment/status/{}".format(res["payment_uid"]),
                cookies=request.COOKIES)
            if payBalance.status_code == 200:
                payBalance = payBalance.json()
                if payBalance["status"] == "CANCELED" or payBalance["status"] == "REVERSED":
                    res.clear()
        mylist = [i for i in reservations if i]
        return JsonResponse(mylist, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def all_hotels(request, hotel_uid):  # only user 'admin'
    """
    GET: "hotel_uid": "5c325464-7445-4147-bd2d-1598641d2248"
    Вытаскиваем все бронирования по отелю
    """
    try:
        data = auth(request)
        if 'admin' not in data['role']:
            return JsonResponse({'detail': 'You are not admin!'})
        hotel_reservations = Reservations.objects.filter(hotel_uid=hotel_uid).all()
        reservations = json.loads(serializers.serialize('json', hotel_reservations))
        for res in reservations:
            payBalance = requests.get(
                "http://localhost:8002/api/v1/payment/status/{}".format(res['fields'].get("payment_uid")),
                cookies=request.COOKIES)
            if payBalance.status_code == 200:
                payBalance = payBalance.json()
                res['fields'].update(payBalance)
            about_hotel = requests.get(
                "http://localhost:8004/api/v1/hotels/{}".format(res['fields'].get("hotel_uid")),
                cookies=request.COOKIES)
            if about_hotel.status_code == 200:
                about_hotel = about_hotel.json()
                res['fields'].update(about_hotel)
            user = requests.get(
                "http://localhost:8001/api/v1/session/user/{}".format(res['fields'].get("user_uid")),
                cookies=request.COOKIES)
            if user.status_code == 200:
                user = user.json()
                res['fields'].update(user)
            loyalty = requests.get(
                "http://localhost:8000/api/v1/loyalty/status/{}".format(res['fields'].get("user_uid")),
                cookies=request.COOKIES)
            if loyalty.status_code == 200:
                loyalty = loyalty.json()
                res['fields'].update(loyalty)
            safe = res['fields']
            res.clear()
            res.update(safe)
        return JsonResponse(reservations, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def all_hotels_statics(request):  # only user 'admin'
    """
    GET: use JWT
    Вытаскиваем все бронирования по отелю
    """
    try:
        data = auth(request)
        if 'admin' not in data['role']:
            return JsonResponse({'detail': 'You are not admin!'})
        hotel_reservations = Reservations.objects.all()
        reservations = json.loads(serializers.serialize('json', hotel_reservations))
        for res in reservations:
            payBalance = requests.get(
                "http://localhost:8002/api/v1/payment/status/{}".format(res['fields'].get("payment_uid")),
                cookies=request.COOKIES)
            if payBalance.status_code == 200:
                payBalance = payBalance.json()
                res['fields'].update(payBalance)
            about_hotel = requests.get(
                "http://localhost:8004/api/v1/hotels/{}".format(res['fields'].get("hotel_uid")),
                cookies=request.COOKIES)
            if about_hotel.status_code == 200:
                about_hotel = about_hotel.json()
                res['fields'].update(about_hotel)
            user = requests.get(
                "http://localhost:8001/api/v1/session/user/{}".format(res['fields'].get("user_uid")),
                cookies=request.COOKIES)
            if user.status_code == 200:
                user = user.json()
                res['fields'].update(user)
            loyalty = requests.get(
                "http://localhost:8000/api/v1/loyalty/status/{}".format(res['fields'].get("user_uid")),
                cookies=request.COOKIES)
            if loyalty.status_code == 200:
                loyalty = loyalty.json()
                res['fields'].update(loyalty)
            safe = res['fields']
            res.clear()
            res.update(safe)
        return JsonResponse(reservations, status=status.HTTP_200_OK, safe=False)
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
