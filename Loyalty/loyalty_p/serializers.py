from rest_framework import serializers
from .models import UserLoyalty
import uuid


class LoyaltySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserLoyalty
        fields = ['user_uid', 'status', 'discount']

    def create(self, validated_data):
        validated_data.pop('role', None)
        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance
