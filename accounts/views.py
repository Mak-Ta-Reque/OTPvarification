import random

# Create your views here.
from django.contrib.auth import login
from django.http import request
from rest_framework import permissions, generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User, PhoneOTP
from django.shortcuts import get_object_or_404
from .serializers import CreateUserSerializer, LoginSerializer, ChangePasswordSerializer, ChangePhoneSerializer
from knox.views import LoginView as KnoxLoginView
from django.conf import settings


class ValidatePhoneSendOTP(APIView):

    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone')
        if phone_number:
            phone = str(phone_number)

            '''
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                return Response({
                    'statue': False,
                    'details': 'Phone number already registered.'
                })
            else:'''
            key = send_otp(phone)
            if key:
                old = PhoneOTP.objects.filter(phone__iexact=phone)
                if old.exists():
                    old = old.first()
                    count = old.count
                    max_otp = settings.OTP_SETTINGS['MAX_OTP']
                    if count > max_otp:
                        return Response({
                            'statue': False,
                            'details': 'OTP limit exceeded.'
                        })
                    old.otp = key
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
                    check_account = User.objects.filter(phone__iexact=phone)
                    if check_account.exists():
                        old.delete()
                        return Response({
                            'status': False,
                            'detail': 'Account account already exists'
                        })

                    else:

                        serializer = CreateUserSerializer(data=temp_data)
                        serializer.is_valid(raise_exception=True)
                        user = serializer.save()
                        user.set_unusable_password()
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


class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePhoneView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePhoneSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():

            # Check  new phone exists in db
            new_phone_user = User.objects.filter(phone__iexact=serializer.data.get("new_phone"))
            if new_phone_user.exists():
                return Response({"new_phone": ["Already has account in this number."]},
                                status=status.HTTP_400_BAD_REQUEST)

            # Verify the new number
            new_phone_user = PhoneOTP.objects.filter(phone__iexact=serializer.data.get("new_phone"))
            if new_phone_user.exists():
                new_phone_user = new_phone_user.first()
                validated = new_phone_user.validated
                if not validated:
                    return Response({"new_phone": ["OTP is not validated, validate the phone number"]},
                                    status=status.HTTP_400_BAD_REQUEST)
                else:
                    new_phone_user.delete()

            else:
                return Response({"new_phone": ["Verify your number first"]},

                                status=status.HTTP_400_BAD_REQUEST)

            if not self.object.phone == serializer.data.get("old_phone"):
                return Response({"old_phone": ["Wrong phone number."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.phone = serializer.data.get("new_phone")
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Phone number updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        login(request, user)
        return super().post(request, format=None)


class DeleteAccountView(generics.UpdateAPIView):
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        phone = PhoneOTP.objects.filter(phone__iexact=self.object.phone)

        if phone.exists():
            old = phone.first()
            validated = old.validated
            if validated:
                self.object.delete()
                old.delete()
                response = {
                    'status': 'success',
                    'code': status.HTTP_200_OK,
                    'message': 'Account deleted successfully.',
                    'data': []
                }

                return Response(response)
            else:
                response = {
                    'status': 'failed',
                    'code': status.HTTP_401_UNAUTHORIZED,
                    'message': 'Validate OTP.',
                    'data': []
                }
                return Response(response)



        else:
            response = {
                'status': 'failed',
                'code': status.HTTP_401_UNAUTHORIZED,
                'message': 'Validate the user.',
                'data': []
            }
            return Response(response)


def send_otp(phone):
    if phone:
        key = random.randint(999, 9999)
        link = settings.OTP_SETTINGS['CLIENT'] + "module=TRANS_SMS&apikey=" + \
               settings.OTP_SETTINGS['API_KEY'] + "&to=" + phone +\
               "&from=" + settings.OTP_SETTINGS['SENDER_ID'] +\
               "&templatename=" + settings.OTP_SETTINGS['TEMPLATE_NAME'] +\
               "&var1=" + phone + "&var2=" +key
        print(link)
        message = request.get(link)
        print(message)
        return key
    else:
        return False
