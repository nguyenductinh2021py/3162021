from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=255, min_length=6, write_only=True)
    email = serializers.EmailField(max_length=255, min_length=6)
    class Meta:
        model = User
        fields = ['username', 'password', 'password2', 'email', 'is_staff']
    
    def create(self, validate_data):
        username = validate_data['username']
        password = validate_data['password']
        password2 = validate_data['password2']
        email = validate_data['email']
        is_staff = validate_data['is_staff']
        if User.objects.filter(username=username):
            raise serializers.ValidationError({"username": "The username is already in use"})
        if User.objects.filter(email=email):
            raise serializers.ValidationError({"email": "The email is already in use"})
        if password != password2:
            raise serializers.ValidationError({"password": "Two password not match"})
        
        user = User(username=username, email=email, is_staff=is_staff)
        user.set_password(password)
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, min_length=4)
    password = serializers.CharField(max_length=64, min_length=6)
    class Meta:
        model=User
        fields=['username', 'password']

    def validate(self, validate_data):
        username=validate_data.get("username", None)
        password=validate_data.get("password", None)

        if not User.objects.filter(username=username) and not User.objects.filter(email=username):
            raise serializers.ValidationError({"username":"username does not exist"})
       
        try:
            user = authenticate(username=User.objects.get(email=username), password=password)
        except:
            user = authenticate(username=username, password=password)
        
        if user is None:
            raise serializers.ValidationError({"password":"password does not exists"})
        validate_data['user']=user
        return validate_data
    
# class LogoutSerializer(serializers.Serializer):
#     access = serializers.CharField()
    
#     def validate(self, attrs):
#         self.token = attrs['access']
#         return attrs
#     def save(self, **kwargs):
#         try:
#             RefreshToken(self.token).blacklist
            