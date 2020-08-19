from django.core.validators import RegexValidator
from django.db import models
from django.db import models
from django.core.mail import send_mail
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import ugettext_lazy as _

from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):

    def create_user(self, phone, password=None, is_staff=False, is_active=True, is_admin=False):
        """
        Creates and saves a User with the given email and password.
        """
        if not phone:
            raise ValueError('User must give a phone number')
        if not password:
            raise ValueError('User must give a password')

        user_obj = self.model(
            phone=phone
        )
        user_obj.set_password(password)

        user_obj.staff = is_staff
        user_obj.admin = is_admin
        user_obj.active = is_active
        user_obj.save(using=self._db)
        return user_obj

    def create_staffuser(self, phone, password=None, ):
        user = self.create_user(phone,
                                password=password,
                                is_staff=True)
        return user

    def create_superuser(self, phone, password):
        user = self.create_user(
            phone,
            password=password,
            is_staff=True,
            is_admin=True
        )
        return user


class User(AbstractBaseUser):
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,14}$', message='Phone number must be in the correct format')
    phone = models.CharField(validators=[phone_regex], max_length=15, unique=True)
    name = models.CharField(max_length=30, blank=True, null=True)
    first_login = models.BooleanField(default=False)
    active = models.BooleanField(_('active'), default=True)
    staff = models.BooleanField(default=False)
    admin = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.phone

    def get_full_name(self):
        if self.name:
            return self.name
        else:
            return self.phone

    def get_sort_name(self):
        return self.phone

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.staff

    @property
    def is_admin(self):
        return self.admin

    @property
    def is_active(self):
        return self.active


class PhoneOTP(models.Model):
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,14}$', message='Phone number must be in the correct format')
    phone = models.CharField(validators=[phone_regex], max_length=15, unique=True)
    otp = models.CharField(max_length=9, blank=True, null=True)
    count = models.IntegerField(default=0, help_text='Number of OTP sent')
    validated = models.BooleanField(default=False, help_text='If its true, that means user validated otp')

    def __str__(self):
        return str(self.phone) + 'is sent ' + str(self.otp)
