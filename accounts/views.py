import random

# Create your views here.
from django.contrib.auth import login
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User, PhoneOTP
from django.shortcuts import get_object_or_404
from .serializers import CreateUserSerializer, LoginSerializer
from knox.views import LoginView as KnoxLoginView


class ValidatePhoneSendOTP(APIView):

    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone')
        if phone_number:
            phone = str(phone_number)
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                return Response({
                    'statue': False,
                    'details': 'Phone number already registered.'
                })
            else:
                key = send_otp(phone)
                if key:
                    old = PhoneOTP.objects.filter(phone__iexact=phone)
                    if old.exists():
                        old = old.first()
                        count = old.count
                        if count > 10:
                            return Response({
                                'statue': False,
                                'details': 'OTP limit exceeded.'
                            })
                        old.count = count + 1
                        old.save()
                        print('count increased ', count)
                        return Response({
                            'statue': True,
                            'details': 'OTP sent successfully.'
                        })

                    else:
                        PhoneOTP.objects.create(
                            phone=phone,
                            otp=key,
                        )
                        return Response({
                            'statue': True,
                            'details': 'OTP sent successfully.'
                        })
                else:
                    return Response({
                        'statue': False,
                        'details': 'Sending OTP error.'
                    })

        else:
            return Response({
                'statue': False,
                'details': 'Phone number is not given in the request.'
            })


class ValidateOTP(APIView):
    '''
    If user already recived otp, post a request with phone and that otp and you will be redirected to set password

    '''

    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        otp_sent = request.data.get('otp', False)

        if phone and otp_sent:
            old = PhoneOTP.objects.filter(phone__iexact=phone)
            if old.exists():
                old = old.first()
                otp = old.otp

                if str(otp_sent) == str(otp):
                    old.validated = True
                    old.save()
                    return Response(
                        {
                            'status': True,
                            'detail': 'OTP matched, please proceed for registration'
                        }
                    )
                else:
                    return Response(
                        {
                            'status': False,
                            'detail': 'OTP is incorrect, please send correct OTP'
                        }
                    )
            else:
                return Response(
                    {
                        'status': False,
                        'detail': 'Please validate phone by sending OTP'
                    }
                )
        else:
            return Response(
                {
                    'status': False,
                    'detail': 'Please provide phone and otp for validation'
                }
            )


class Register(APIView):
    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        password = request.data.get('password', False)

        if phone and password:
            old = PhoneOTP.objects.filter(phone__iexact=phone)
            if old.exists():
                old = old.first()
                validated = old.validated

                if validated:
                    temp_data = {
                        'phone': phone,
                        'password': password
                    }
                    serializer = CreateUserSerializer(data=temp_data)
                    serializer.is_valid(raise_exception=True)
                    user = serializer.save()
                    old.delete()
                    return Response({
                        'status': True,
                        'detail': 'Account created'
                    })
                else:
                    return Response({
                        'status': False,
                        'detail': 'Please verify OTP'
                    })




            else:
                return Response({
                    'status': False,
                    'detail': 'Please verify phone number first'
                })



        else:
            return Response({
                'status': False,
                'detail': 'Both phone number and password must be submitted'
            })


class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        login(request, user)
        return super().post(request, format=None)


def send_otp(phone):
    if phone:
        key = random.randint(999, 9999)
        return key
    else:
        return False
