# Generated by Django 3.2 on 2021-06-22 19:24

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('session', '0002_users_ava'),
    ]

    operations = [
        migrations.RenameField(
            model_name='users',
            old_name='ava',
            new_name='avatar',
        ),
    ]