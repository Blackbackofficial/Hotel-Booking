from django import forms


class LoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))


class UserRegistrationForm(forms.Form):
    first_name = forms.CharField(label='Name', widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(label='Surname', widget=forms.TextInput(attrs={'class': 'form-control'}))
    username = forms.CharField(label='Login', widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(label="E-mail", widget=forms.EmailInput(attrs={'class': 'form-control'}))
    password = forms.CharField(label='Password', widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    password2 = forms.CharField(label='Repeat password', widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    avatar = forms.ImageField(label='Avatar:', widget=forms.FileInput(attrs={'class': 'form-control'}), required=False)


class NewHotel(forms.Form):
    title = forms.CharField(label='Name:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    short_text = forms.CharField(label='Description:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    rooms = forms.IntegerField(label='Number of rooms:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    cities = forms.CharField(label='City:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    location = forms.CharField(label='Address:', widget=forms.TextInput(attrs={'class': 'form-control'}))
    cost = forms.IntegerField(label="Cost one room:", widget=forms.TextInput(attrs={'class': 'form-control'}))
    photo = forms.ImageField(label='Hotel photos:', widget=forms.FileInput(attrs={'class': 'form-control'}), required=False)


class DeleteHotel(forms.Form):
    hotel_uid = forms.CharField(label='Hotel UUID:', widget=forms.TextInput(attrs={'class': 'form-control'}))
