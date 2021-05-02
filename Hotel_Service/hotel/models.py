from django.db import models
import uuid


class Hotels(models.Model):
    hotel_uid = models.UUIDField(default=uuid.uuid4, editable=True, unique=True)
    title = models.CharField(max_length=25)
    short_text = models.CharField(max_length=25)
    photo = models.ImageField(null=True, blank=True, verbose_name=u"фото", upload_to='static/images/')
    location = models.CharField(max_length=80)
    rooms = models.IntegerField(default=0)

    def __str__(self):
        return self.discount
