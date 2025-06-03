from django.shortcuts import redirect
from django.conf import settings
from django.contrib import messages
from administracion.models import usuario_base

class RestrictAppMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Si el usuario no está autenticado, redirigir a login solo para rutas protegidas
        if not request.user.is_authenticated:
            if request.path.startswith(('/autenticacion/usuario/', '/autenticacion/ejecutivo/', '/administracion/')):
                return redirect(settings.LOGIN_URL)
            return self.get_response(request)

        if request.user.is_superuser:
            return self.get_response(request)

        # Obtener el registro de usuario_base asociado usando el correo
        user_base = None
        try:
            user_base = usuario_base.objects.get(correo=request.user.email)
        except usuario_base.DoesNotExist:
            messages.error(request, "No se encontró un registro de usuario asociado. Contacta al administrador.")
            return redirect(settings.LOGIN_REDIRECT_URL)  # Redirige a '/', evitando bucle
        except usuario_base.MultipleObjectsReturned:
            messages.error(request, "Se encontraron múltiples registros con este correo. Contacta al administrador.")
            return redirect(settings.LOGIN_REDIRECT_URL)

        # Determinar si el usuario es un "ejecutivo" (is_staff=True y rol="ejecutivo")
        is_ejecutivo = request.user.is_staff and user_base.rol == "ejecutivo"

        # Restricciones por ruta
        if request.path.startswith('/administracion/'):
            if not is_ejecutivo:
                messages.error(request, "No tienes permiso para acceder a esta sección.")
                return redirect(settings.LOGIN_REDIRECT_URL)

        elif request.path.startswith('/autenticacion/ejecutivo/'):
            if not is_ejecutivo:
                messages.error(request, "Solo los ejecutivos pueden acceder a esta sección.")
                return redirect('/autenticacion/usuario/')

        elif request.path.startswith('/autenticacion/usuario/'):
            if is_ejecutivo:
                messages.error(request, "Los ejecutivos no pueden acceder a esta sección.")
                return redirect('/autenticacion/ejecutivo/')

        return self.get_response(request)