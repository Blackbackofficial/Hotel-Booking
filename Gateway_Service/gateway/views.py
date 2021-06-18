from django.shortcuts import render
from rest_framework.exceptions import AuthenticationFailed
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from Gateway_Service.settings import JWT_KEY
from django.forms.models import model_to_dict
from .forms import LoginForm, UserRegistrationForm, NewHotel, DeleteHotel
from django.core import serializers
from django.http import HttpResponseRedirect, JsonResponse
from rest_framework import status
from confluent_kafka import Producer
from datetime import datetime
import pytz
import sys
import os
import requests
import json
import jwt
import re

FAILURES = 3
TIMEOUT = 6

# Time zone
tz_MOS = pytz.timezone('Europe/Moscow')

# Kafka
conf = {
    'bootstrap.servers': 'glider-01.srvs.cloudkafka.com:9094, glider-02.srvs.cloudkafka.com:9094, '
                         'glider-03.srvs.cloudkafka.com:9094',
    'session.timeout.ms': 6000,
    'default.topic.config': {'auto.offset.reset': 'smallest'},
    'security.protocol': 'SASL_SSL',
    'sasl.mechanisms': 'SCRAM-SHA-256',
    'sasl.username': '41pfiknb',
    'sasl.password': '4r-NRj1TnbY-WTt5zVE-zPMhFr8qXFx9'
}


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def login(request):  #
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
    q_session = session.json()
    q_session.update({"username": request.data["username"],
                      "date": datetime.now(tz_MOS).strftime('%Y-%m-%d %H:%M:%S %Z%z')})
    producer(q_session, '41pfiknb-users')
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def register(request):  #
    """
    POST: {
          "role": "admin", вставляется только при админке или "user"
          "username": "qwerty",
          "name": "Ivan",
          "last_name": "Chernov",
          "email": "Chernov-Ivan.1997@yandex.ru",
          "password": "qwerty"
          }
    """
    session = requests.post("http://localhost:8001/api/v1/session/register", json=request.data)
    if session.status_code != 200:
        return JsonResponse(session.json(), status=status.HTTP_400_BAD_REQUEST)
    session = session.json()["user_uid"]
    request.data.update({"user_uid": session})
    loyalty = requests.post("http://localhost:8000/api/v1/loyalty/create", json=request.data)
    if loyalty.status_code != 200:
        return JsonResponse(loyalty.json(), status=status.HTTP_400_BAD_REQUEST)
    q_session = {"username": request.data["username"], "detail": 'Register',
                 "date": datetime.now(tz_MOS).strftime('%Y-%m-%d %H:%M:%S %Z%z')}
    producer(q_session, '41pfiknb-users')
    return JsonResponse({'success': 'register & create loyalty'}, status=status.HTTP_200_OK)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def logout(request):  #
    """
    POST: in the post only JWT
    """
    session = requests.post("http://localhost:8001/api/v1/session/logout", cookies=request.COOKIES)
    if session.status_code != 200:
        return JsonResponse(session.json(), status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse({'success': 'logout'}, status=status.HTTP_200_OK)

    user = requests.get("http://localhost:8001/api/v1/session/user/{}".format(session.json()["user_uid"]),
                        cookies=request.COOKIES).json()
    q_session = {"username": user["username"], "detail": 'Logout',
                 "date": datetime.now(tz_MOS).strftime('%Y-%m-%d %H:%M:%S %Z%z')}
    producer(q_session, '41pfiknb-users')
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
    _users = requests.get("http://localhost:8001/api/v1/session/users", cookies=session.cookies)
    if _users.status_code != 200:
        return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse(_users.json(), status=status.HTTP_200_OK, safe=False)
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
          "location": "Leninskiy Prospekt 95, Москва, Россия",
          "cost": 3992
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


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET', 'POST'])
def create_booking_or_all(request):
    """
    POST: {
          "hotel_uid": "80b91c03-8792-4e7b-b898-8bee843b37fa"
          "date_start": "2013-03-30",
          "date_end": "2021-07-17",
          "comment": "somebody",
          } use JWT for user_uid && "price": == cost
    GET:  all user's booking JWT
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        booking = requests.get("http://localhost:8003/api/v1/booking/", cookies=session.cookies)
        if booking.status_code != 200:
            return JsonResponse(booking.json(), status=status.HTTP_400_BAD_REQUEST)
    else:  # POST
        # узнаем цену отеля
        hotel = requests.get("http://localhost:8004/api/v1/hotels/{}"
                             .format(request.data['hotel_uid']), json=request.data, cookies=session.cookies)
        if hotel.status_code != 200:
            return JsonResponse(hotel.json(), status=status.HTTP_400_BAD_REQUEST)
        hotel = hotel.json()
        request.data.update({"price": hotel["cost"]})
        #  создаем бронь
        booking = requests.post("http://localhost:8003/api/v1/booking/", json=request.data, cookies=session.cookies)
        if booking.status_code != 200:
            return JsonResponse(booking.json(), status=status.HTTP_400_BAD_REQUEST)
        #  подсчитываем количество броней для определения нужно ли повышать лояльность или нет
        booking_all = requests.get("http://localhost:8003/api/v1/booking/", cookies=session.cookies)
        if booking_all.status_code != 200:
            return JsonResponse(booking_all.json(), status=status.HTTP_400_BAD_REQUEST)
        len_booking = booking_all.json()
        l_status = requests.get("http://localhost:8000/api/v1/loyalty/balance", cookies=session.cookies)
        if l_status.status_code != 200:
            return JsonResponse(l_status.json(), status=status.HTTP_400_BAD_REQUEST)
        l_status = l_status.json()['status']

        # Up Loyalty
        if 20 < len(len_booking) < 35 and l_status == 'None':  # BRONZE
            loyaltyUP = requests.patch("http://localhost:8000/api/v1/loyalty/edit", json={"active": "UP"},
                                       cookies=session.cookies)
            if loyaltyUP.status_code != 200:
                return JsonResponse(loyaltyUP.json(), status=status.HTTP_400_BAD_REQUEST)
        elif 35 < len(len_booking) < 50 and l_status == 'BRONZE':  # SILVER
            loyaltyUP = requests.patch("http://localhost:8000/api/v1/loyalty/edit", json={"active": "UP"},
                                       cookies=session.cookies)
            if loyaltyUP.status_code != 200:
                return JsonResponse(loyaltyUP.json(), status=status.HTTP_400_BAD_REQUEST)
        elif 50 < len(len_booking) and l_status == 'SILVER':  # GOLD
            loyaltyUP = requests.patch("http://localhost:8000/api/v1/loyalty/edit", json={"active": "UP"},
                                       cookies=session.cookies)
            if loyaltyUP.status_code != 200:
                return JsonResponse(loyaltyUP.json(), status=status.HTTP_400_BAD_REQUEST)
        #  при бронировании вычитаем комнату
        hotel = requests.patch("http://localhost:8004/api/v1/hotels/{}/rooms"
                               .format(request.data['hotel_uid']),
                               json={"reservation": "Done"}, cookies=session.cookies)
        if hotel.status_code != 200:
            return JsonResponse(hotel.json(), status=status.HTTP_400_BAD_REQUEST)
        booking = booking.json()
        payBalance = requests.get(
            "http://localhost:8002/api/v1/payment/status/{}".format(booking.get("payment_uid")),
            cookies=request.COOKIES)
        if payBalance.status_code == 200:
            payBalance = payBalance.json()
            booking.update(payBalance)
        about_hotel = requests.get(
            "http://localhost:8004/api/v1/hotels/{}".format(booking.get("hotel_uid")),
            cookies=request.COOKIES)
        if about_hotel.status_code == 200:
            about_hotel = about_hotel.json()
            booking.update(about_hotel)
        user = requests.get(
            "http://localhost:8001/api/v1/session/user/{}".format(booking.get("user_uid")),
            cookies=request.COOKIES)
        if user.status_code == 200:
            user = user.json()
            booking.update(user)
        loyalty = requests.get(
            "http://localhost:8000/api/v1/loyalty/status/{}".format(booking.get("user_uid")),
            cookies=request.COOKIES)
        if loyalty.status_code == 200:
            loyalty = loyalty.json()
            booking.update(loyalty)

    producer(booking, '41pfiknb-payment')
    response = JsonResponse(booking, status=status.HTTP_200_OK, safe=False)

    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def one_booking(request, booking_uid):
    """
    GET: use JWT && booking_uid
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    booking_one = requests.get("http://localhost:8003/api/v1/booking/{}".format(booking_uid), cookies=session.cookies)
    if booking_one.status_code != 200:
        return JsonResponse(booking_one.json(), status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse(booking_one.json(), status=status.HTTP_200_OK, safe=False)
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def all_booking_hotels(request, hotel_uid):
    """
    GET: use JWT && booking_uid "hotel_uid": "80b91c03-8792-4e7b-b898-8bee843b37fa"
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    booking_hotel = requests.get("http://localhost:8003/api/v1/booking/hotels/{}".format(hotel_uid),
                                 cookies=session.cookies)
    if booking_hotel.status_code != 200:
        return JsonResponse(booking_hotel.json(), status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse(booking_hotel.json(), status=status.HTTP_200_OK, safe=False)
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def pay_booking(request, booking_uid):
    """
    POST: use JWT && booking_uid "hotel_uid": "80b91c03-8792-4e7b-b898-8bee843b37fa"
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    booking_status = requests.get("http://localhost:8003/api/v1/booking/{}".format(booking_uid),
                                  cookies=session.cookies)
    if booking_status.status_code != 200:
        return JsonResponse(booking_status.json(), status=status.HTTP_400_BAD_REQUEST)
    if booking_status.json()["status"] == 'PAID':
        return JsonResponse({"error": "Is paid"}, status=status.HTTP_400_BAD_REQUEST)
    booking_pay = requests.post("http://localhost:8003/api/v1/booking/pay/{}".format(booking_uid),
                                cookies=session.cookies)
    if booking_pay.status_code != 200:
        return JsonResponse(booking_pay.json(), status=status.HTTP_400_BAD_REQUEST)
    response = JsonResponse(booking_pay.json(), status=status.HTTP_200_OK, safe=False)
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def close_booking(request, booking_uid):
    """
    POST: use JWT && booking_uid "hotel_uid": "80b91c03-8792-4e7b-b898-8bee843b37fa"
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    # узнаем статус
    booking_status = requests.get("http://localhost:8003/api/v1/booking/{}".format(booking_uid),
                                  cookies=session.cookies)
    if booking_status.status_code != 200:
        return JsonResponse(booking_status.json(), status=status.HTTP_400_BAD_REQUEST)
    booking_status = booking_status.json()["status"]
    if booking_status == 'PAID' and booking_status != 'REVERSED' and booking_status != 'CANCELED':
        booking_r = requests.post("http://localhost:8003/api/v1/booking/reversed/{}".format(booking_uid),
                                  cookies=session.cookies)
        if booking_r.status_code != 200:
            return JsonResponse(booking_r.json(), status=status.HTTP_400_BAD_REQUEST)
        booking_status = 'REVERSED'

    if booking_status == 'NEW' and booking_status != 'REVERSED' and booking_status != 'CANCELED':
        booking_r = requests.post("http://localhost:8003/api/v1/booking/canceled/{}".format(booking_uid),
                                  cookies=session.cookies)
        if booking_r.status_code != 200:
            return JsonResponse(booking_r.json(), status=status.HTTP_400_BAD_REQUEST)
        booking_status = 'CANCELED'

    response = JsonResponse({'success': booking_status}, status=status.HTTP_200_OK, safe=False)
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
    return response


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def report_booking(request):
    """
        GET: use JWT
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    # достаем отчет по бронированию
    report = requests.get("http://localhost:8006/api/v1/reports/booking", cookies=session.cookies)
    if report.status_code == 200:
        report = report.content.decode('utf8').replace("'", '"')
        report = json.loads(report)
        return JsonResponse(report, status=status.HTTP_200_OK)
    return JsonResponse({"detail": "No content in queue"}, status=status.HTTP_204_NO_CONTENT)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def report_user(request):
    """
        GET: use JWT
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    # достаем отчет по пользователям: логирование, разлогирование, регистрация
    report = requests.get("http://localhost:8006/api/v1/reports/users", cookies=session.cookies)
    if report.status_code == 200:
        report = report.content.decode('utf8').replace("'", '"')
        report = json.loads(report)
        return JsonResponse(report, status=status.HTTP_200_OK)
    return JsonResponse({"detail": "No content in queue"}, status=status.HTTP_204_NO_CONTENT)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def report_hotels(request):
    """
        GET: use JWT
    """
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
        else:
            return JsonResponse({"error": "Internal error"}, status=status.HTTP_400_BAD_REQUEST)
    # достаем отчет по пользователям: логирование, разлогирование, регистрация
    report = requests.get("http://localhost:8006/api/v1/reports/hotels", cookies=session.cookies)
    if report.status_code == 200:
        report = report.content.decode('utf8').replace("'", '"')
        report = json.loads(report)
        return JsonResponse(report, safe=False, status=status.HTTP_200_OK)
    return JsonResponse({"detail": "No content in queue or error"}, status=status.HTTP_204_NO_CONTENT)


# VIEW
def index(request):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    response = render(request, 'index.html', {'user': data})

    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
        if is_authenticated else response.delete_cookie('jwt')
    return response


def make_login(request):
    error = None
    if request.method == "GET":
        form = LoginForm()
    if request.method == "POST":
        form = LoginForm(data=request.POST)
        session = requests.post('http://localhost:8005/api/v1/login',
                                json={"username": request.POST.get('username'),
                                      "password": request.POST.get('password')})
        if session.status_code == 200:
            response = HttpResponseRedirect('/index')
            response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
            return response
        else:
            session = session.content.decode('utf8').replace("'", '"')
            error = json.loads(session)['detail']
    return render(request, 'login.html', {'form': form, 'error': error})


def add_hotel_admin(request):
    error = None
    is_authenticated, request, session = cookies(request)
    data = auth(request)

    if request.method == "GET":
        form = NewHotel()
    if request.method == "POST":
        form = NewHotel(data=request.POST)
        new_hotel = requests.post('http://localhost:8005/api/v1/hotel',
                                  json={'title': form.data['title'], 'short_text': form.data['short_text'],
                                        'rooms': form.data['rooms'], 'cost': form.data['cost'],
                                        'location': form.data['location']}, cookies=request.COOKIES)
        error = 'success'
        if new_hotel.status_code != 200:
            error = new_hotel.json()['message']

    response = render(request, 'new_hotel.html', {'form': form, 'user': data, 'error': error})

    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
        if is_authenticated else response.delete_cookie('jwt')
    return response


def admin(request):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    if data['role'] != 'admin':
        response = HttpResponseRedirect('/index')
        response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
        return response
    response = render(request, 'admin.html', {'user': data})
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
        if is_authenticated else response.delete_cookie('jwt')
    return response


def delete_hotel_admin(request):
    error = None
    is_authenticated, request, session = cookies(request)
    data = auth(request)

    if request.method == "GET":
        form = DeleteHotel()
    if request.method == "POST":
        form = DeleteHotel(data=request.POST)
        new_hotel = requests.delete('http://localhost:8005/api/v1/hotels/{}'.format(form.data['hotel_uid']),
                                  cookies=request.COOKIES)
        error = 'success'
        if new_hotel.status_code != 204:
            try:
                error = new_hotel.json()['message']
            except Exception:
                error = 'Parse error'

    response = render(request, 'delete_hotel.html', {'form': form, 'user': data, 'error': error})

    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
        if is_authenticated else response.delete_cookie('jwt')
    return response


def all_users(request):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    if data['role'] != 'admin':
        response = HttpResponseRedirect('/index')
        response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
        return response
    _users = requests.get("http://localhost:8005/api/v1/users", cookies=request.COOKIES).json()
    response = render(request, 'all_users.html', {'all_users': _users, 'user': data})
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
        if is_authenticated else response.delete_cookie('jwt')
    return response


def make_logout(request):
    session = requests.get("http://localhost:8005/api/v1/logout", cookies=request.COOKIES)
    if session.status_code == 200:
        response = HttpResponseRedirect('/index')
        response.delete_cookie('jwt')
        return response
    return render(request, 'index.html')


def balance(request):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    loyalty = requests.get("http://localhost:8000/api/v1/loyalty/status/{}".format(data['user_uid']),
                           cookies=request.COOKIES).json()
    user = requests.get("http://localhost:8001/api/v1/session/user/{}".format(data['user_uid']),
                        cookies=request.COOKIES).json()
    response = render(request, 'balance.html', {'loyalty': loyalty, 'user': user})
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
        if is_authenticated else response.delete_cookie('jwt')
    return response


def registration(request):
    error = None
    form = UserRegistrationForm()

    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        # validation
        if form.data['password'] != form.data['password2']:
            return render(request, 'signup.html', {'form': form, 'error': 'Password mismatch'})
        if not re.compile("^([A-Za-z0-9]+)+$").match(form.data['username']):
            return render(request, 'signup.html', {'form': form, 'error': 'No valid login'})
        session = requests.post('http://localhost:8005/api/v1/register',
                                json={"username": form.data['username'], "name": form.data['first_name'],
                                      "last_name": form.data['last_name'], "password": form.data['password'],
                                      "email": form.data['email']})
        error = 'success'
        if session.status_code != 200:
            session = session.content.decode('utf8').replace("'", '"')
            error = "email is not unique" if 'email' in session else "username is not unique"

    return render(request, 'signup.html', {'form': form, 'error': error})


def delivery_callback(err, msg):
    if err:
        sys.stderr.write('%% Message failed delivery: %s\n' % err)
    else:
        sys.stderr.write('%% Message delivered to %s [%d]\n' % (msg.topic(), msg.partition()))


# Queue Kafka
def producer(data, topic):
    topic = topic

    p = Producer(**conf)

    line = str(data)
    try:
        p.produce(topic, line.rstrip(), callback=delivery_callback)
    except BufferError:
        sys.stderr.write('%% Local producer queue is full (%d messages awaiting delivery): try again\n' % len(p))
    p.poll(0)

    sys.stderr.write('%% Waiting for %d deliveries\n' % len(p))
    p.flush()


def auth(request):
    token = request.COOKIES.get('jwt')

    if not token:
        return
    try:
        payload = jwt.decode(token, JWT_KEY, algorithms=['HS256'], options={"verify_exp": False})
    except jwt.DecodeError:
        return None
    payload.pop('exp')
    payload.pop('iat')
    return payload


def cookies(request):
    is_authenticated = False
    session = requests.get("http://localhost:8001/api/v1/session/validate", cookies=request.COOKIES)
    if session.status_code != 200:
        if session.status_code == 403:
            session = requests.get("http://localhost:8001/api/v1/session/refresh", cookies=request.COOKIES)
            is_authenticated = True
        elif session.status_code == 401:
            pass
        else:
            request.delete_cookie('jwt')
    else:
        is_authenticated = True
    return is_authenticated, request, session
