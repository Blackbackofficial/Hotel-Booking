from rest_framework import serializers
from .models import Payment
import uuid


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['payment_uid', 'status', 'price']

    def create(self, validated_data):
        validated_data.pop('role', None)
        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance
