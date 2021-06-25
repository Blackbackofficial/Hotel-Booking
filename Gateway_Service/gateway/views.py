import ast
import datetime

from django.core.paginator import Paginator
from django.shortcuts import render
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from Gateway_Service.settings import JWT_KEY
from .forms import LoginForm, UserRegistrationForm, NewHotel, DeleteHotel
from django.http import HttpResponseRedirect, JsonResponse, Http404
from rest_framework import status
from confluent_kafka import Producer
from datetime import datetime as dt
from random import choices
from string import ascii_letters, digits
import pytz
import sys
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
                      "date": dt.now(tz_MOS).strftime('%Y-%m-%d %H:%M:%S %Z%z')})
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
                 "date": dt.now(tz_MOS).strftime('%Y-%m-%d %H:%M:%S %Z%z')}
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
                 "date": dt.now(tz_MOS).strftime('%Y-%m-%d %H:%M:%S %Z%z')}
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
    hotel = requests.post("http://localhost:8004/api/v1/hotels/", json=request.data, cookies=session.cookies)
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
        l_status = l_status.json()['status_loyalty']

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
        booking = booking.json()
        payBalance = requests.get("http://localhost:8002/api/v1/payment/status/{}".format(booking.get("payment_uid")),
                                  cookies=request.COOKIES)
        if payBalance.status_code == 200:
            payBalance = payBalance.json()
            booking.update(payBalance)
        about_hotel = requests.get("http://localhost:8004/api/v1/hotels/{}".format(booking.get("hotel_uid")),
                                   cookies=request.COOKIES)
        if about_hotel.status_code == 200:
            about_hotel = about_hotel.json()
            booking.update(about_hotel)
        user = requests.get("http://localhost:8001/api/v1/session/user/{}".format(booking.get("user_uid")),
                            cookies=request.COOKIES)
        if user.status_code == 200:
            user = user.json()
            booking.update(user)
        loyalty = requests.get("http://localhost:8000/api/v1/loyalty/status/{}".format(booking.get("user_uid")),
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
    _allhotels = requests.get("http://localhost:8004/api/v1/hotels", cookies=request.COOKIES).json()

    if len(_allhotels) != 0:
        title = "Our hotels"
        paginator = Paginator(_allhotels, 10)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        response = render(request, 'index.html', {'allhotels': _allhotels, 'page_obj': page_obj, \
                                              'title': title, 'user': data})

    else:
        title = "Нет отелей :("
        response = render(request, 'index.html', {'title': title, 'user': data})

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


def hotel_info(request, hotel_uid):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    try:
        hotel = requests.get("http://localhost:8004/api/v1/hotels/{}"
                             .format(hotel_uid), cookies=request.COOKIES).json()
        response = render(request, 'hotel_info.html', {'hotel_info': hotel, 'user': data})
    except:
        error = "Не удалось вывести информацию об отеле. Повторите попытку позже"
        response = render(request, 'hotel_info.html', {'error': error, 'user': data})

    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
        if is_authenticated else response.delete_cookie('jwt')
    return response


def add_booking(request):
    is_authenticated, request, session = cookies(request)
    user = auth(request)
    if request.method == 'POST':
        data = request.POST
        if request.POST['date_start'] > request.POST['date_end'] or request.POST['date_start'] < datetime.datetime.now():
            dateerror = "Неверный ввод дат"
            hotel = requests.get("http://localhost:8004/api/v1/hotels/{}"
                                 .format(request.POST['hotel_uid']), cookies=request.COOKIES).json()
            response = render(request, 'hotel_info.html', {'dateerror': dateerror, 'hotel_info': hotel, 'user': data})
        else:
            booking = requests.post("http://localhost:8003/api/v1/booking/",
                                    json={"hotel_uid": data["hotel_uid"],
                                          "date_start": data["date_start"],
                                          "date_end": data["date_end"],
                                          "comment": data["comment"],
                                          "price": int(data["price"])}, cookies=request.COOKIES)
            if booking.status_code == 200:
                response = HttpResponseRedirect('/booking_info/{}'.format(booking.json()['booking_uid']))
            else:
                error = "Что-то пошло не так. Повторите попытку позже"
                response = render(request, 'hotel_info.html', {'error': error, 'user': data})
        response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
            if is_authenticated else response.delete_cookie('jwt')
        return response


def booking_info(request, booking_uid):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    try:
        booking = requests.get("http://localhost:8003/api/v1/booking/{}"
                             .format(booking_uid), cookies=session.cookies).json()
        hotel = requests.get("http://localhost:8004/api/v1/hotels/{}"
                             .format(booking['hotel_uid']), cookies=session.cookies).json()
        payment = requests.get("http://localhost:8002/api/v1/payment/status/{}"
                             .format(booking['payment_uid']), cookies=session.cookies).json()
        date_start = datetime.datetime.strptime(booking['date_start'], "%Y-%m-%d")
        date_end = datetime.datetime.strptime(booking['date_end'], "%Y-%m-%d")
        period = date_end - date_start
        totalcost = int(hotel['cost'])*(period.days+1)
        response = render(request, 'user_booking.html', {'booking': booking, 'hotel': hotel, 'payment': payment, 'user': data,\
                                                         'totalcost': totalcost})
    except:
        bookerror = "Не удалось отобразить бронирование. Повторите попытку"
        response = render(request, 'user_booking.html', {'bookerror': bookerror, 'user': data})
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
        if is_authenticated else response.delete_cookie('jwt')
    return response


def pay_room(request, payment_uid):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    if request.method == 'POST':
        booking = requests.get("http://localhost:8003/api/v1/booking/{}"
                             .format(request.POST['booking_uid']), cookies=session.cookies).json()
        hotel = requests.get("http://localhost:8004/api/v1/hotels/{}"
                             .format(booking['hotel_uid']), cookies=session.cookies).json()
        payment = requests.get("http://localhost:8002/api/v1/payment/status/{}"
                             .format(booking['payment_uid']), cookies=session.cookies).json()
        pay = requests.post("http://localhost:8002/api/v1/payment/pay/{}"
                               .format(payment_uid), cookies=request.COOKIES)
        if pay.status_code == 200:
            response = HttpResponseRedirect('/booking_info/{}'.format(request.POST['booking_uid']))
        else:
            error = "Не удалось провести оплату!"
            response = render(request, 'user_booking.html',
                      {'booking': booking, 'hotel': hotel, 'payment': payment, 'error': error, 'user': data, \
                       'totalcost': request.POST['totalcost']})

        response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
            if is_authenticated else response.delete_cookie('jwt')
        return response


def del_booking(request, booking_uid):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    if request.method == "POST":
        book = ast.literal_eval(request.POST['booking'])
        hot = ast.literal_eval(request.POST['hotel'])
        pay = ast.literal_eval(request.POST['payment'])
        if request.POST['status'] == "NEW":
            delbook = requests.delete("http://localhost:8003/api/v1/booking/canceled/{}"
                                 .format(booking_uid), cookies=request.COOKIES)
            if delbook.status_code == 200:
                success = "Бронирование удалено"
                response = render(request, 'user_booking.html', {'bookdel':success, 'user': data})
                # response = HttpResponseRedirect('/balance')
            else:
                error = "Что-то пошло не так, повторите попытку"
                response = render(request, 'user_booking.html', {'booking': book, 'hotel': hot, \
                                                                 'payment': pay, 'error':error, 'user': data})
        else:
            payment = requests.post("http://localhost:8003/api/v1/booking/reversed/{}"
                                 .format(booking_uid), cookies=request.COOKIES)
            if payment.status_code == 200:
                delbook = requests.delete("http://localhost:8003/api/v1/booking/canceled/{}"
                                     .format(booking_uid), cookies=request.COOKIES)
                if delbook.status_code == 200:
                    success = "Бронирование удалено"
                    response = render(request, 'user_booking.html', {'bookdel':success, 'user': data})
                else:
                    error = "Ошибка снятия бронирования"
                    response = render(request, 'user_booking.html', {'booking': book, 'hotel': hot, \
                                                                 'payment': pay, 'error':error, 'user': data})
            else:
                error = "Ошибка возврата средств"
                response = render(request, 'user_booking.html', {'booking': book, 'hotel': hot, \
                                                                 'payment': pay, 'error':error, 'user': data})

        response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
            if is_authenticated else response.delete_cookie('jwt')
        return response

def search_hotel_booking(request):
    is_authenticated, request, session = cookies(request)
    user = auth(request)
    if request.method == 'POST':
        data = request.POST
        search = requests.post("http://localhost:8004/api/v1/hotels/date",
                                json={"date_start": data["date_start"],
                                      "date_end": data["date_end"],
                                      "city": data["city"]}, cookies=request.COOKIES)
        if len(search.json()) != 0:
            title = "Доступные отели в городе "+str(data["city"])+" c "+str(data["date_start"])+" по "+str(data["date_end"])

            paginator = Paginator(search.json(), 10)
            page_number = request.GET.get('page')
            page_obj = paginator.get_page(page_number)
            response = render(request, 'index.html', {'allhotels': search, 'page_obj': page_obj, \
                                                      'title': title, 'user': user})
        else:
            title = "По Вашему запросу ничего не найдено"
            response = render(request, 'index.html', {'title': title, 'user': user})
        response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
            if is_authenticated else response.delete_cookie('jwt')
        return response


def add_hotel_admin(request):
    error = None
    is_authenticated, request, session = cookies(request)
    data = auth(request)

    if request.method == "GET":
        form = NewHotel()
    if request.method == "POST":
        form = NewHotel(data=request.POST)
        # сохраним фото в gateway/static/images/
        try:
            filename = ''.join(choices(ascii_letters + digits, k=10)) + '.jpg'
            with open(f'gateway/static/images/{filename}', 'wb') as image:
                files = request.FILES["photo"].read()
                image.write(files)
            new_hotel = requests.post("http://localhost:8004/api/v1/hotels/",
                                      json={'title': form.data['title'], 'short_text': form.data['short_text'],
                                            'rooms': form.data['rooms'], 'cost': form.data['cost'],
                                            'cities': form.data['cities'],
                                            'location': form.data['location'], 'file': f'images/{filename}'},
                                      cookies=request.COOKIES)
            error = 'success'
            if new_hotel.status_code != 200:
                error = new_hotel.json()['message']
        except:
            error = 'No photo'
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


def static_booking(request):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    if data['role'] != 'admin':
        response = HttpResponseRedirect('/index')
        response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
        return response

    report = requests.get("http://localhost:8006/api/v1/reports/booking", cookies=session.cookies)
    if report.status_code == 200:
        report = report.content.decode('utf8').replace("'", '"')
        report = json.loads(report)
        dictlist = list()
        for key, value in report.items():
            temp = [key, value]
            dictlist.append(temp)
    else:
        dictlist = None

    response = render(request, 'static_booking.html', {'static_booking': dictlist, 'user': data})
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


def users_static(request):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    if data['role'] != 'admin':
        response = HttpResponseRedirect('/index')
        response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
        return response
    try:
        static_users = requests.get("http://localhost:8005/api/v1/reports/users", cookies=request.COOKIES).json()
        dictlist = list()
        for key, value in static_users.items():
            temp = [key, value]
            dictlist.append(temp)
    except Exception:
        dictlist = None

    response = render(request, 'users_static.html', {'all_users': dictlist, 'user': data})
    response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True) \
        if is_authenticated else response.delete_cookie('jwt')
    return response


def all_booking_static(request):
    is_authenticated, request, session = cookies(request)
    data = auth(request)
    uid = None
    if data['role'] != 'admin':
        response = HttpResponseRedirect('/index')
        response.set_cookie(key='jwt', value=session.cookies.get('jwt'), httponly=True)
        return response
    try:
        static_booking = requests.get("http://localhost:8006/api/v1/reports/hotels", cookies=request.COOKIES).json()
        static_booking = sorted(static_booking, key=lambda k: k['hotel_uid'])
    except Exception:
        static_booking = None
    if request.method == "POST":
        if len(request.POST['hotel_uid']) > 0:
            if request.POST['status'] == "all":
                try:
                    s = requests.get("http://localhost:8006/api/v1/reports/hotels", cookies=request.COOKIES).json()
                    static_booking = []
                    for static in s:
                        if static['hotel_uid'] == request.POST['hotel_uid']:
                            static_booking.append(static)
                    static_booking = sorted(static_booking, key=lambda k: k['hotel_uid'])
                    uid = request.POST['hotel_uid']
                except Exception:
                    static_booking = None

            if request.POST['status'] == "new/paid":
                try:
                    s = requests.get("http://localhost:8006/api/v1/reports/hotels", cookies=request.COOKIES).json()
                    static_booking = []
                    for static in s:
                        if static['hotel_uid'] == request.POST['hotel_uid'] and static['status'] == "NEW":
                            static_booking.append(static)
                        elif static['hotel_uid'] == request.POST['hotel_uid'] and static['status'] == "PAID":
                            static_booking.append(static)
                    static_booking = sorted(static_booking, key=lambda k: k['hotel_uid'])
                    uid = request.POST['hotel_uid']
                except Exception:
                    static_booking = None

            if request.POST['status'] == "canceled/reversed":
                try:
                    s = requests.get("http://localhost:8006/api/v1/reports/hotels", cookies=request.COOKIES).json()
                    static_booking = []
                    for static in s:
                        if static['hotel_uid'] == request.POST['hotel_uid'] and static['status'] == "CANCELED":
                            static_booking.append(static)
                        elif static['hotel_uid'] == request.POST['hotel_uid'] and static['status'] == "REVERSED":
                            static_booking.append(static)
                    static_booking = sorted(static_booking, key=lambda k: k['hotel_uid'])
                    uid = request.POST['hotel_uid']
                except Exception:
                    static_booking = None
        else:
            if request.POST['status'] == "all":
                try:
                    static_booking = requests.get("http://localhost:8006/api/v1/reports/hotels", cookies=request.COOKIES).json()
                    static_booking = sorted(static_booking, key=lambda k: k['hotel_uid'])
                except Exception:
                    static_booking = None

            if request.POST['status'] == "new/paid":
                try:
                    s = requests.get("http://localhost:8006/api/v1/reports/hotels", cookies=request.COOKIES).json()
                    static_booking = []
                    for static in s:
                        if static['status'] == "NEW" or static['status'] == "PAID":
                            static_booking.append(static)
                    static_booking = sorted(static_booking, key=lambda k: k['hotel_uid'])
                except Exception:
                    static_booking = None

            if request.POST['status'] == "canceled/reversed":
                try:
                    s = requests.get("http://localhost:8006/api/v1/reports/hotels", cookies=request.COOKIES).json()
                    static_booking = []
                    for static in s:
                        if static['status'] == "CANCELED" or static['status'] == "REVERSED":
                            static_booking.append(static)
                    static_booking = sorted(static_booking, key=lambda k: k['hotel_uid'])
                except Exception:
                    static_booking = None

    response = render(request, 'all_booking_hotels.html', {'all_booking': static_booking, 'user': data, 'uid': uid})
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
    try:
        loyalty = requests.get("http://localhost:8000/api/v1/loyalty/status/{}".format(data['user_uid']),
                               cookies=request.COOKIES).json()
        user = requests.get("http://localhost:8001/api/v1/session/user/{}".format(data['user_uid']),
                            cookies=request.COOKIES).json()
        _allbook = requests.get("http://localhost:8003/api/v1/booking/", cookies=request.COOKIES).json()

        sort = sorted(_allbook, key=lambda x: (x['date_create'], x['date_end']), reverse=True)
        curr = []
        hist = []
        currhotel = []
        histhotel = []
        currpay = []
        histpay = []
        for s in sort:
            payment = requests.get("http://localhost:8002/api/v1/payment/status/{}"
                             .format(s['payment_uid']), cookies=session.cookies).json()
            if datetime.datetime.strptime(s['date_end'], "%Y-%m-%d") > datetime.datetime.now() and payment['status'] == 'NEW':
                ch = requests.get("http://localhost:8004/api/v1/hotels/{}"
                             .format(s['hotel_uid']), cookies=session.cookies).json()
                curr.append(s)
                currhotel.append(ch)
                currpay.append(payment)
            elif datetime.datetime.strptime(s['date_end'], "%Y-%m-%d") > datetime.datetime.now() and payment['status'] == 'PAID':
                ch = requests.get("http://localhost:8004/api/v1/hotels/{}"
                             .format(s['hotel_uid']), cookies=session.cookies).json()
                curr.append(s)
                currhotel.append(ch)
                currpay.append(payment)
            else:
                hh = requests.get("http://localhost:8004/api/v1/hotels/{}"
                             .format(s['hotel_uid']), cookies=session.cookies).json()
                hist.append(s)
                histhotel.append(hh)
                histpay.append(payment)
        currbookhot = zip(curr, currhotel, currpay)
        histbookhot = zip(hist, histhotel, histpay)
        response = render(request, 'balance.html', {'loyalty': loyalty, 'user': user, 'currbookhot': currbookhot, \
                                                    'histbookhot': histbookhot})
    except:
        usererror = "Не удалось отобразить данные. Попробуйте позднее"
        response = render(request, 'balance.html', {'user': user, 'usererror': usererror})
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
        if len(request.FILES) == 0:
            return render(request, 'signup.html', {'form': form, 'error': 'No Photo'})
        # сохраним фото в gateway/static/images/avatars
        filename = ''.join(choices(ascii_letters + digits, k=10)) + '.jpg'
        with open(f'gateway/static/images/avatars/{filename}', 'wb') as image:
            files = request.FILES["avatar"].read()
            image.write(files)
        session = requests.post('http://localhost:8005/api/v1/register',
                                json={"username": form.data['username'], "name": form.data['first_name'],
                                      "last_name": form.data['last_name'], "password": form.data['password'],
                                      "email": form.data['email'], "avatar": f'images/avatars/{filename}'})
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
