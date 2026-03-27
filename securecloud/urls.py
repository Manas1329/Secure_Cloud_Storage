"""URL configuration for securecloud project."""

from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, path

from accounts.views import home

admin.site.site_header = "SecureCloud Control Center"
admin.site.site_title = "SecureCloud Admin"
admin.site.index_title = "Security Operations"

urlpatterns = [
    path('', home, name='home'),
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('storage/', include('storage.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
