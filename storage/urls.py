from django.urls import path

from storage import views

app_name = "storage"

urlpatterns = [
    path("files/", views.file_list, name="files"),
    path("upload/", views.upload_file, name="upload"),
    path("files/<int:file_id>/delete/", views.delete_file, name="delete"),
    path("files/<int:file_id>/download/", views.download_file, name="download"),
    path("files/<int:file_id>/view/", views.view_file, name="view"),
    path("files/<int:file_id>/share/", views.share_file, name="share"),
    path("shared/", views.shared_files, name="shared"),
    path("history-fragment/", views.download_history_data, name="history-fragment"),
]
