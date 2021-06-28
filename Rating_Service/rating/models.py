from django.db import models
import uuid


# Create your models here.

class CommentLikes(models.Model):
    comment_uid = models.UUIDField(default=uuid.uuid4, blank=False, unique=True)
    hotel_uid = models.UUIDField(default=uuid.uuid4, blank=False)
    user_uid = models.UUIDField(default=uuid.uuid4, blank=False)
    username = models.CharField(max_length=255)
    avatar = models.CharField(max_length=30, default="images/avatars/non.jpeg", blank=False)
    comment_text = models.TextField(blank=False)
    comment_date = models.DateTimeField(auto_now_add=True)
    comment_likes = models.IntegerField(default=0)
    comment_dislikes = models.IntegerField(default=0)

    def __str__(self):
        return str(self.comment_uid)


class HotelLikes(models.Model):
    hotel_uid = models.UUIDField(default=uuid.uuid4, blank=False, unique=True)
    hotel_likes = models.IntegerField(default=0)
    hotel_dislikes = models.IntegerField(default=0)

    def __str__(self):
        return str(self.hotel_uid)


class LikeComment(models.Model):
    comment_uid = models.UUIDField(default=uuid.uuid4, blank=False)
    user_uid = models.UUIDField(default=uuid.uuid4, blank=False)
    like = models.BooleanField(default=False)
    dislike = models.BooleanField(default=False)

    def __str__(self):
        return str(self.comment_uid)


class LikeHotel(models.Model):
    user_uid = models.UUIDField(default=uuid.uuid4, blank=False)
    hotel_uid = models.UUIDField(default=uuid.uuid4, blank=False)
    like = models.BooleanField(default=False)
    dislike = models.BooleanField(default=False)

    def __str__(self):
        return str(self.hotel_uid)
