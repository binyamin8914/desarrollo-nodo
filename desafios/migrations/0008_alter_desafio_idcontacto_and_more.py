# Generated by Django 5.1.4 on 2025-01-14 22:32

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('administracion', '0001_initial'),
        ('desafios', '0007_alter_desafio_descripciondesafio'),
    ]

    operations = [
        migrations.AlterField(
            model_name='desafio',
            name='idContacto',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='administracion.contactoempresa'),
        ),
        migrations.AlterField(
            model_name='postulaciondesafio',
            name='idContacto',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='administracion.contactoempresa'),
        ),
        migrations.AlterField(
            model_name='postulaciondesafio',
            name='idEmpresa',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='administracion.empresa'),
        ),
        migrations.AlterField(
            model_name='desafio',
            name='idEmpresa',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='administracion.empresa'),
        ),
        migrations.AlterField(
            model_name='desafio',
            name='descripcionDesafio',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='desafio',
            name='documentacionProblema',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.DeleteModel(
            name='contactoEmpresa',
        ),
        migrations.DeleteModel(
            name='Empresa',
        ),
    ]
