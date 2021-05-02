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