from django.shortcuts import render
from authentication.serializers import RegisterSerializer, LoginSerializer
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from rest_framework.response import Response
class RegisterView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            response = {
                "username": serializer.data['username'],
                "status_code": status.HTTP_201_CREATED
            }
            return Response(response, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = (AllowAny, )

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
      
        login(request, user)
        access = AccessToken.for_user(user)
        response = {
            "id": user.id,
            "username": user.username,
            "status.code": status.HTTP_200_OK,
            "token": str(access)
        }
        return Response(response, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = (AllowAny, )

    def post(self, request):
        access_token = request.data['refresh']
        token = RefreshToken(access_token)
        token.blacklist()
        return Response("Successful Logout", status=status.HTTP_200_OK)
    
