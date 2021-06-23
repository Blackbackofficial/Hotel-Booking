from django.db import models
import uuid


class Reservations(models.Model):
    booking_uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=True)
    hotel_uid = models.UUIDField(default=uuid.uuid4, editable=True)
    user_uid = models.UUIDField(default=uuid.uuid4, editable=True)
    payment_uid = models.UUIDField(default=uuid.uuid4, editable=True, unique=True)
    date_create = models.DateTimeField(auto_now=True)
    date_start = models.DateField(auto_now=False)
    date_end = models.DateField(auto_now=False)
    comment = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.discount
