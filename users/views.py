
from rest_framework import permissions
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.datetime_safe import datetime

from shared.utilit import send_email
from .models import User, DONE, CODE_VERIFIED, NEW, VIA_EMAIL, VIA_PHONE
from .serializers import SignUpSerializer



class CreateUser(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = SignUpSerializer



class VerifyAPIView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self,request,*args,**kwargs):
        user = self.request.user
        code = self.request.data.get("code")

        self.check_verify(user,code)
        return Response(
            data={
                "success":True,
                "auth_status": user.auth_status,
                "access": user.token()['access'],
                "refresh": user.token()['refresh_token']
            }
        )
    @staticmethod
    def check_verify(user,code):

        verifies = user.verify_code.filter(expiration_time__gte=datetime.now(),code=code,is_confirmed=False)
        if not verifies.exists():
            data = {
                'message':"Tasdiqlash kodingiz xato yoki eskirgan "
            }
            raise ValidationError(data)
        else:
            verifies.update(is_confirmed=True)
        if user.auth_status not in NEW:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True





class GetNewVerification(APIView):
    def get(self,request,*args,**kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email,code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number,code)
        else:
            data = {
                "message":"email yoki telifon nommeringiz xato"
            }
            raise ValidationError(data)
        return Response(
            {
                'success':True,
                "message":"Tasdiqlash kodingiz qaytadan jonatildi"
            }

        )


    @staticmethod
    def check_verification(user):
        verifies = user.verify_code.filter(expiration_time__gte=datetime.now(),is_confirmed=False)
        if verifies.exists():
            data = {
                'messege':"Kodingiz hali yaroqli biroz kutib turing"
            }
            raise ValidationError(data)
