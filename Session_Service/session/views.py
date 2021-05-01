from rest_framework.exceptions import AuthenticationFailed, ValidationError, ParseError
from rest_framework.response import Response
from django.core import serializers
from .models import Users
from .serializers import UserSerializer
from Session_Service.settings import SECRET_KEY
from rest_framework.decorators import api_view
from django.http import JsonResponse
from rest_framework import status
import json
import datetime
import jwt
import requests


# API
@api_view(['POST'])
def register(request):
    try:
        if 'role' not in request.data:
            request.data.update({'role': 'user'})
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login(request):
    try:
        username = request.data['username']
        password = request.data['password']
    except KeyError:
        raise ValidationError('Incorrect data')

    user = Users.objects.filter(username=username).first()

    if user is None:
        raise AuthenticationFailed('User not found!')

    if not user.check_password(password):
        raise AuthenticationFailed('Incorrect password!')

    payload = {
        'user_uid': str(user.user_uid),
        'role': str(user.role),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=50),
        'iat': datetime.datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode('utf-8')

    response = Response()

    response.set_cookie(key='jwt', value=token, httponly=True)
    response.data = {
        'detail': 'Authenticated'
    }
    return response


@api_view(['GET'])
def validate(request):
    token = request.COOKIES.get('jwt')

    if not token:
        raise AuthenticationFailed('Null token!')

    try:
        jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Unauthenticated!')

    return JsonResponse({'detail': 'Authenticated'}, status=status.HTTP_200_OK)


@api_view(['GET'])
def refresh(request):
    token = request.COOKIES.get('jwt')

    if not token:
        raise AuthenticationFailed('Unauthenticated!')

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], options={"verify_exp": False})
    except jwt.ExpiredSignatureError:
        raise ParseError('Parse error!')

    payload = {
        'user_uid': str(payload['user_uid']),
        'role': str(payload['role']),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=50),
        'iat': datetime.datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode('utf-8')

    response = Response()

    response.set_cookie(key='jwt', value=token, httponly=True)
    response.data = {
        'jwt': token
    }
    return response


@api_view(['GET'])
def users(request):
    try:
        data = auth(request)
        if 'admin' not in data['role']:
            return Response({'detail': 'You are not admin!'})
        users = Users.objects.all()
        users_json = json.loads(serializers.serialize('json', users))
        return Response(users_json, status=status.HTTP_200_OK)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def logout(request):
    response = Response()
    response.delete_cookie('jwt')
    response.data = {
        'detail': 'success'
    }
    return response


# subsidiary
def auth(request):
    token = request.COOKIES.get('jwt')

    if not token:
        raise AuthenticationFailed('Unauthenticated!')

    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], options={"verify_exp": False})
    payload.pop('exp')
    payload.pop('iat')
    return payload
