from rest_framework.exceptions import AuthenticationFailed
from circuitbreaker import circuit
from confluent_kafka import Consumer, KafkaException, KafkaError
from rest_framework.decorators import api_view
from django.http import JsonResponse
from Report_Service.settings import JWT_KEY
from rest_framework import status
import requests
import json
import jwt
import sys
import os

FAILURES = 3
TIMEOUT = 6

# Kafka
conf = {
    'bootstrap.servers': 'glider-01.srvs.cloudkafka.com:9094, glider-02.srvs.cloudkafka.com:9094, '
                         'glider-03.srvs.cloudkafka.com:9094',
    'group.id': "%s-consumer" % '41pfiknb',
    'session.timeout.ms': 6000,
    'default.topic.config': {'auto.offset.reset': 'smallest'},
    'security.protocol': 'SASL_SSL',
    'sasl.mechanisms': 'SCRAM-SHA-256',
    'sasl.username': '41pfiknb',
    'sasl.password': '4r-NRj1TnbY-WTt5zVE-zPMhFr8qXFx9'
}


# API
@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def report_by_booking(request):
    """
    POST: {
          "user_uid": "b5f342ce-2419-4a17-8800-b921e90b5fbf"
          }
    """
    try:
        auth(request)
        data = consumer('41pfiknb-payment')
        if len(data) != 0:
            dictOfList = {i: data[i] for i in range(0, len(data))}
            return JsonResponse(dictOfList, status=status.HTTP_200_OK)
        return JsonResponse(data, status=status.HTTP_204_NO_CONTENT)
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


# subsidiary
def auth(request):
    token = request.COOKIES.get('jwt')

    if not token:
        raise AuthenticationFailed('Unauthenticated!')

    payload = jwt.decode(token, JWT_KEY, algorithms=['HS256'], options={"verify_exp": False})
    payload.pop('exp')
    payload.pop('iat')
    return payload


def bytes_to_json(byte):
    my_json = byte.decode('utf8').replace("'", '"')
    data = json.loads(my_json)
    return data


# Queue Kafka
def consumer(topic):
    byte = ''
    resp = list()
    topics = ['{}'.format(topic)]

    c = Consumer(**conf)
    c.subscribe(topics)
    try:
        i = 0
        while True:
            msg = c.poll(timeout=1.0)
            if msg is None and i < 6:
                i += 1
                continue
            if i >= 6:
                c.close()
                return resp
            if msg.error():
                # Error or event
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    # End of partition event
                    sys.stderr.write('%% %s [%d] reached end at offset %d\n' %
                                     (msg.topic(), msg.partition(), msg.offset()))
                elif msg.error():
                    # Error
                    raise KafkaException(msg.error())
            else:
                # Proper message
                sys.stderr.write('%% %s [%d] at offset %d with key %s:\n' %
                                 (msg.topic(), msg.partition(), msg.offset(),
                                  str(msg.key())))
                byte = msg.value()
                resp.append(bytes_to_json(byte))
                i = 0

    except KeyboardInterrupt:
        sys.stderr.write('%% Aborted by user\n')

    # Close down consumer to commit final offsets.
    c.close()
    return resp
