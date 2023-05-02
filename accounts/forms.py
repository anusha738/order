from django.forms import ModelForm
from accounts.models import *
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class OrderForm(ModelForm):
    class Meta:
        model = Order
        fields = '__all__' #order so tae model ko kyi pee shi tha mhya field ko form a nay nae te sout
        #fields = ['status', 'name'] --> lo chin tae field ko pl swl htote ml so list nae pya

class CustomerProfile(ModelForm):
    class Meta:
        model = Customer
        fields = ['email', 'phone', 'profile_pic']
        # fields = '__all__'
        # exclude = ['user']

class RegisterForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']