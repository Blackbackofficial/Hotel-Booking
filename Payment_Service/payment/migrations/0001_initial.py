# Generated by Django 3.2 on 2021-05-01 12:17

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Payment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('payment_uid', models.UUIDField(default=uuid.uuid4, unique=True)),
                ('status', models.CharField(max_length=10)),
                ('price', models.IntegerField(default=0)),
            ],
        ),
    ]