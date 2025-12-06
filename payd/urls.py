"""
URL configuration for payd project.
"""

from django.contrib import admin
from django.urls import path

from api.views import payd

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", payd.urls),
]
