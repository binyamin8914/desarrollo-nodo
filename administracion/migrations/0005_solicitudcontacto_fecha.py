# Generated by Django 5.1.4 on 2025-01-28 23:45

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('administracion', '0004_solicitudcontacto'),
    ]

    operations = [
        migrations.AddField(
            model_name='solicitudcontacto',
            name='fecha',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
