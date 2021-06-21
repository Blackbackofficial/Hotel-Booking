from rest_framework import serializers
from .models import Hotels
import uuid


class HotelsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hotels
        fields = ['hotel_uid', 'title', 'short_text', 'location', 'rooms', 'cost', 'cities']

    def create(self, validated_data):
        validated_data.pop('role', None)
        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance
