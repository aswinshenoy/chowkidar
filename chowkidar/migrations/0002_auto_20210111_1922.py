# Generated by Django 3.1.5 on 2021-01-11 19:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chowkidar', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='refreshtoken',
            name='ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='refreshtoken',
            name='userAgent',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
