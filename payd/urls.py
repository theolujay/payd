"""
URL configuration for payd project.
"""

from django.contrib import admin
from django.urls import path
from django.views.generic.base import RedirectView

from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView


from api.endpoints import api

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
    path("", RedirectView.as_view(url="/api/", permanent=False)),
    path("docs/", RedirectView.as_view(url="/api/docs", permanent=False)),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
