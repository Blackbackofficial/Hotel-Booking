from rest_framework import serializers
from .models import Reservations
import uuid


class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reservations
        fields = ['hotel_uid', 'user_uid', 'payment_uid', 'date_start', 'date_end', 'comment', 'date_create']

    def create(self, validated_data):
        validated_data.pop('role', None)
        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance
