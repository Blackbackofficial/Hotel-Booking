from django.db import models
import uuid


class UserLoyalty(models.Model):
    user_uid = models.UUIDField(default=uuid.uuid4, editable=True)
    status = models.CharField(max_length=10)
    discount = models.IntegerField(default=0)

    def __str__(self):
        return self.discount
