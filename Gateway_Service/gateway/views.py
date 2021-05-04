from django.shortcuts import render
from rest_framework.exceptions import AuthenticationFailed, ValidationError, ParseError
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from Hotel_Service.settings import JWT_KEY
from django.forms.models import model_to_dict
from django.core import serializers
from django.http import JsonResponse
from rest_framework import status
from .models import Hotels
import requests
import json
import jwt

FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET', 'DELETE'])
def about_or_delete(request, hotel_uid):
    request