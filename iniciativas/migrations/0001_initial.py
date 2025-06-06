# Generated by Django 5.1.4 on 2025-02-11 22:38

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('desafios', '0012_alter_desafio_imagen'),
    ]

    operations = [
        migrations.CreateModel(
            name='PostulacionIniciativa',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('titulo', models.CharField(max_length=255)),
                ('descripcion', models.TextField()),
                ('pregunta', models.CharField(max_length=255)),
                ('origen', models.CharField(max_length=255)),
                ('fecha_creacion', models.DateTimeField(auto_now_add=True)),
                ('desafio', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='iniciativas', to='desafios.desafio')),
            ],
        ),
    ]
