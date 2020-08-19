from django.contrib import admin
from django.urls import path, re_path
from .views import ValidatePhoneSendOTP, ValidateOTP, Register, LoginAPI, ChangePasswordView, ChangePhoneView, DeleteAccountView
from knox import views as knox_view

urlpatterns = [
    re_path(r'^validate_phone/', ValidatePhoneSendOTP.as_view()),
    re_path(r'^validate_otp/$', ValidateOTP.as_view()),
    re_path(r'^register/$', Register.as_view()),
    re_path(r'^change_password/$', ChangePasswordView.as_view()),
    re_path(r'^change_phone_number/$', ChangePhoneView.as_view()),
    re_path(r'^login/$', LoginAPI.as_view()),
    re_path(r'^logout/$', knox_view.LogoutAllView.as_view()),
    re_path(r'^delete_account/$',DeleteAccountView.as_view() ),


]
