from django.shortcuts import render
from circuitbreaker import circuit
from rest_framework.decorators import api_view
from rest_framework.parsers import JSONParser
from django.http import JsonResponse


FAILURES = 3
TIMEOUT = 6


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def create_loyalty(request):
    i = 1
    return '<h1>efwf</h1>'


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def about_loyalty(request):
    i = 1


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['PATCH'])
def edit_loyalty(request):
    i = 1


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['DELETE'])
def delete_loyalty(request):
    i = 1
