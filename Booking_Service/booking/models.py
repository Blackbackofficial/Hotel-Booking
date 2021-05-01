from django.db import models
import uuid


class Reservations(models.Model):
    hotel_uid = models.UUIDField(default=uuid.uuid4, editable=True, unique=True)
    user_uid = models.UUIDField(default=uuid.uuid4, editable=True, unique=True)
    payment_uid = models.UUIDField(default=uuid.uuid4, editable=True, unique=True)
    date_start = models.DateField(auto_now=False)
    date_end = models.DateField(auto_now=False)
    comment = models.CharField(max_length=255)

    def __str__(self):
        return self.discount
