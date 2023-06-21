
from rest_framework import permissions
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.datetime_safe import datetime
from rest_framework_simplejwt.views import TokenObtainPairView

from shared.utilit import send_email
from .models import User, DONE, CODE_VERIFIED, NEW, VIA_EMAIL, VIA_PHONE
from .serializers import SignUpSerializer, ChangeUserIndormation, ChangeUserPhotoSerializers,LoginSerializers


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
    permission_classes = (IsAuthenticated,)
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



class ChangeUserIndormationView(UpdateAPIView):
    permission_classes = [IsAuthenticated,]
    serializer_class = ChangeUserIndormation,
    http_method_names = ['patch','put']

    def get_object(self):
        return self.request.user
    def update(self, request, *args, **kwargs):
        super(ChangeUserIndormationView,self).update(request,*args,**kwargs)
        data = {
            'success':True,
            'message':'User Update successfully',
            'auth_status': self.request.user.auth_status,
        }


        return Response(data,status=200)


    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserIndormationView,self).partial_update(request,*args,**kwargs)
        data = {
            "success":True,
            "message":"Partial Update SuccessFully",
            "auth_status": self.request.user.auth_status,
        }

        return Response(data,status=200)

class ChangeUserPhotoView(APIView):

    permission_classes = (IsAuthenticated,)


    def put(self,request,*args,**kwargs):
        serialers = ChangeUserPhotoSerializers(data=request.data)
        if serialers.is_valid():
            user = request.user
            serialers.update(user,serialers.validated_data)
            return Response(
                {
                    "message":"Rasm o'zgartirildi "

                },status=200

            )
        return Response(
            serialers.errors,status=400
        )


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializers










