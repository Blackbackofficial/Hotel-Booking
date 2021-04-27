from django.db import models


class UserLoyalty(models.Model):
    user_uid = models.IntegerField(default=0)
    status = models.CharField(max_length=10)
    discount = models.IntegerField(default=0)

    def __str__(self):
        return self.discount
