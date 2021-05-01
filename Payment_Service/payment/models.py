from django.db import models
import uuid


class Payment(models.Model):
    payment_uid = models.UUIDField(default=uuid.uuid4, editable=True, unique=True)
    status = models.CharField(max_length=10)
    price = models.IntegerField(default=0)

    def __str__(self):
        return self.discount
