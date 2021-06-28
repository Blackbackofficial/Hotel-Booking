from rest_framework import serializers
from .models import LikeHotel, LikeComment, HotelLikes, CommentLikes
import uuid


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommentLikes
        fields = ['comment_uid', 'hotel_uid', 'username', 'avatar', 'comment_text', 'comment_date', 'comment_likes',
                  'comment_dislikes']

    def create(self, validated_data):
        validated_data.pop('role', None)
        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance

class HotelSerializer(serializers.ModelSerializer):
    class Meta:
        model = HotelLikes
        fields = ['hotel_uid', 'hotel_likes', 'hotel_dislikes']

    def create(self, validated_data):
        validated_data.pop('role', None)
        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance

class HotelLikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = LikeHotel
        fields = ['hotel_uid', 'user_uid', 'like', 'dislike']

    def create(self, validated_data):
        validated_data.pop('role', None)
        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance


class CommentLikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = LikeComment
        fields = ['comment_uid', 'user_uid', 'like', 'dislike']

    def create(self, validated_data):
        validated_data.pop('role', None)
        instance = self.Meta.model(**validated_data)
        instance.save()
        return instance