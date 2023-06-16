from django.contrib.auth.password_validation import validate_password

from users.models import User,UserConfirmation,DONE,VIA_PHONE,VIA_EMAIL,CODE_VERIFIED,PHOTO_EXPIRE
from rest_framework import exceptions,serializers
from django.db.models import Q
from rest_framework.exceptions import ValidationError
from shared.utilit import check_email_or_phone, send_email, send_phone_code


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self,*args,**kwargs):
        super(SignUpSerializer,self).__init__(*args,**kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)


    class Meta:
        model = User
        fields = (
            'id',
            'auth_type',
            'auth_status',

        )
        extra_kwargs = {
            'auth_type':{'read_only':True,'required':False},
            'auth_status':{'read_only':True,'required':False},
        }

    def create(self, validated_data):
        user = super(SignUpSerializer,self).create(validated_data)
        print(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email,code)
            print(code)
        elif user.auth_type == VIA_PHONE:

            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
            #send_phone_code(user.phone_number,code)
        user.save()
        return user


    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        print(data)
        user_input = str(data.get("email_phone_number")).lower()
        input_type = check_email_or_phone(user_input)
        if input_type == 'email':
            data = {
                'email':user_input,
                'auth_type':VIA_EMAIL
            }
        elif input_type == 'phone':
            data = {
                'phone_number':user_input,
                'auth_type':VIA_PHONE
            }
        else:
            data = {
                'success':False,
                "message":"Telifon raqam yoki Email pochtaingizni jonating "
            }
            raise ValidationError(data)


        return data
    def validate_email_phone_number(self,value):
        value = value.lower()
        if value and User.objects.filter(email=value).exists():
            data = {
                'success':False,
                'message':'Bu email allaqachon malumotlar bazasida bor'
            }
            raise ValidationError(data)
        elif value and User.objects.filter(phone_number=value).exists():
            data = {
                'success': False,
                'message': 'Bu email allaqachon malumotlar bazasida bor'
            }
            raise ValidationError(data)

        return value

    def to_representation(self, instance):
        print('to_rep',instance)
        data = super(SignUpSerializer,self).to_representation(instance)
        data.update(instance.token())
        return data

class ChangeUserIndormation(serializers.Serializer):
    first_name = serializers.CharField(required=True, write_only=True),
    last_name = serializers.CharField(required=True, write_only=True),
    username = serializers.CharField(required=True, write_only=True),
    password = serializers.CharField(required=True, write_only=True),
    confirm_password = serializers.CharField(required=True, write_only=True),

    def validate(self, data):
        password = data.get('password',None)
        confirm_password = data.get('confirm_password',None)
        if password != confirm_password:
            raise ValidationError(
                {
                    'message':"parolingiz bir biriga mos kelmadi"
                }
            )
        if password:
            validate_password(password)
            validate_password(confirm_password)
        return data


    def validate_username(self,username):
        if len(username) < 5 or len(username) > 35:
            raise ValidationError(
                {
                    'message':"Sizning Usernameingiz 5 ta belgidan kam bolmasin yoki 35 ta belgidan kop bolmasligi kerak"
                }
            )
        if username.isdigit():
            raise ValidationError(
                {
                    "message":""
                }
            )


















