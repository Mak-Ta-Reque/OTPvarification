from django.contrib import admin
from django.urls import path, re_path
from .views import ValidatePhoneSendOTP, ValidateOTP, Register, LoginAPI
from knox import views as knox_view

urlpatterns = [
    re_path(r'^validate_phone/', ValidatePhoneSendOTP.as_view()),
    re_path(r'^validate_otp/$', ValidateOTP.as_view()),
    re_path(r'^register/$', Register.as_view()),
    re_path(r'^login/$', LoginAPI.as_view()),
    re_path(r'^logout/$', knox_view.LogoutView.as_view()),

]
