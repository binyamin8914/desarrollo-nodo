# Generated by Django 5.1.4 on 2025-01-30 23:58

import administracion.models
import django.core.files.storage
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('administracion', '0007_alter_empresa_pais'),
    ]

    operations = [
        migrations.AlterField(
            model_name='documento',
            name='archivo',
            field=models.FileField(storage=django.core.files.storage.FileSystemStorage(location='C:\\Users\\ajdhd\\Escritorio\\NODO_\\administracion'), upload_to=administracion.models.document_upload_path),
        ),
    ]
