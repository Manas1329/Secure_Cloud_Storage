from django import forms

from accounts.models import User
from storage.models import SecureFile, SecureFileShare


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

    share_username = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={"class": "input", "placeholder": "Viewer username (optional)"}),
    )
    share_permission = forms.ChoiceField(
        required=False,
        choices=SecureFileShare.Permission.choices,
        widget=forms.Select(attrs={"class": "input"}),
    )


class ShareFileForm(forms.Form):
    username = forms.CharField(
        required=True,
        widget=forms.TextInput(attrs={"class": "input", "placeholder": "Viewer username"}),
    )
    permission = forms.ChoiceField(
        choices=SecureFileShare.Permission.choices,
        widget=forms.Select(attrs={"class": "input"}),
    )
    remove_access = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "check"}),
    )
