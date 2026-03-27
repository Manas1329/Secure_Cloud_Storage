from django import forms

from accounts.models import User
from storage.models import SecureFile


class UploadFileForm(forms.ModelForm):
    source_file = forms.FileField(required=True)

    class Meta:
        model = SecureFile
        fields = ("description", "expiry_date", "download_limit")
        widgets = {
            "description": forms.Textarea(attrs={"class": "input", "rows": 3, "placeholder": "Describe this file"}),
            "expiry_date": forms.DateTimeInput(attrs={"class": "input", "type": "datetime-local"}),
            "download_limit": forms.NumberInput(attrs={"class": "input", "min": 0, "placeholder": "0 for unlimited"}),
        }

    share_with = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(role=User.Role.VIEWER),
        required=False,
        widget=forms.SelectMultiple(attrs={"class": "input"}),
    )


class ShareFileForm(forms.Form):
    viewers = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(role=User.Role.VIEWER),
        widget=forms.SelectMultiple(attrs={"class": "input"}),
        required=False,
    )
