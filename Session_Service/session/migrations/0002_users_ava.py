# Generated by Django 3.2 on 2021-06-22 19:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('session', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='users',
            name='ava',
            field=models.CharField(default='N', max_length=30),
            preserve_default=False,
        ),
    ]