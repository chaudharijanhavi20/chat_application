from rest_framework import serializers
from .models import *


class SignUpSerializer(serializers.ModelSerializer):
    class Meta:

        model = SignUp
        abstract = True
        fields = '_all_'


class PasswordSerializer(serializers.ModelSerializer):
    class Meta:

        model = Passwords
        abstract = True
        fields = '__all__'


class MessageSerializer(serializers.ModelSerializer):
    class Meta:

        model = Messages
        abstract = True
        fields = '_all_'
