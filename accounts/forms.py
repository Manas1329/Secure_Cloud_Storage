from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm

from accounts.models import User


class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={"class": "input", "placeholder": "Username"}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={"class": "input", "placeholder": "Password"}))


class RegisterForm(UserCreationForm):
    class Meta:
        model = User
        fields = ("username", "email", "role", "password1", "password2")

    role = forms.ChoiceField(
        choices=[(User.Role.USER, "User"), (User.Role.VIEWER, "Viewer")],
        widget=forms.Select(attrs={"class": "input"}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "input")


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "input")
