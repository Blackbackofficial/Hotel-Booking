from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid


class Users(AbstractUser):
    user_uid = models.UUIDField(default=uuid.uuid4)
    role = models.CharField(max_length=30)
    avatar = models.CharField(max_length=30)
    name = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    username = models.CharField(unique=True, max_length=255)

    # REQUIRED_FIELDS = []
    USERNAME_FIELD = 'username'
