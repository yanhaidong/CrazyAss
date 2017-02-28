from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser,PermissionsMixin
)
from django.utils.translation import ugettext_lazy as _
from django.utils.safestring import mark_safe

# Create your models here.


class Host(models.Model):
    '''主机信息'''
    #主机名  分辨是干什么的
    hostname = models.CharField(max_length=64)
    # ip地址   GenericIPAddressField支持ipv4 和ipv6  unique是否唯一
    ip_addr = models.GenericIPAddressField(unique=True)
    #端口号 PositiveIntegerField  正数制字段  default 默认是22
    port = models.PositiveIntegerField(default=22)
    #关联的机房
    idc = models.ForeignKey("IDC")
    # 机器是否已经被启动   BooleanField布尔值字段  默认是启动的
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return "%s(%s)"%(self.hostname,self.ip_addr)
    class Meta:
        verbose_name_plural = "主机信息"
class IDC(models.Model):
    '''机房信息'''
    name = models.CharField(max_length=64,unique=True)

    #执行IDC方法的时候 调用 name
    def __str__(self):
        return self.name
    class Meta:
        verbose_name_plural = "机房信息"

class HostGroup(models.Model):
    '''主机组'''
    name = models.CharField(max_length=64,unique=True)
    #关联 绑定主机和主机账号 表   可以为空  可以不填
    bind_hosts = models.ManyToManyField("BindHost",blank=True,null=True)

    def __str__(self):
        return self.name
    class Meta:
        verbose_name_plural = "主机组"

class UserProfileManager(BaseUserManager):
    def create_user(self, email, name, password=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            name=name,
        )

        user.set_password(password)
        self.is_active = True
        user.save(using=self._db)
        return user

    def create_superuser(self,email, name, password):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
        )
        user.is_active = True
        user.is_superuser = True
        #user.is_admin = True
        user.save(using=self._db)
        return user
    class Meta:
        verbose_name_plural = "客户资料"

class UserProfile(AbstractBaseUser,PermissionsMixin):
    """堡垒机账号"""

    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
        null=True
    )
    password = models.CharField(_('password'), max_length=128,
                                help_text=mark_safe('''<a href='password/'>修改密码</a>'''))
    name = models.CharField(max_length=32)
    is_active = models.BooleanField(default=True)
    # is_admin = models.BooleanField(default=False)

    bind_hosts = models.ManyToManyField("BindHost", blank=True)
    host_groups = models.ManyToManyField("HostGroup", blank=True)

    objects = UserProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def get_full_name(self):
        # The user is identified by their email address
        return self.email

    def get_short_name(self):
        # The user is identified by their email address
        return self.email

    def __str__(self):  # __unicode__ on Python 2
        return self.email

    class Meta:
        verbose_name_plural = "堡垒机账号"
    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_active


class HostUser(models.Model):
    """主机登录账户"""
    #判断登录的类型  是密码登录还是 密钥登录
    auth_type_choices = ((0,'ssh-password'),(1,'ssh-key'))
    # SmallIntegerField 小整数字段，类似于IntegerField，取值范围依赖于数据库特性，[-32768 ,32767]的取值范围对Django所支持的数据库都是安全的
    auth_type = models.SmallIntegerField(choices=auth_type_choices, default=0)
    username = models.CharField(max_length=64)
    password = models.CharField(max_length=128, blank=True, null=True)

    #密码验证
    def __str__(self):
        return "%s:%s" %(self.username,self.password)

    #三个联合唯一
    class Meta:
        unique_together = ('auth_type','username','password')
        verbose_name_plural = "主机登录账户"
class BindHost(models.Model):
    """绑定主机和主机账号"""
    host = models.ForeignKey("Host")
    host_user = models.ForeignKey("HostUser")

    def __str__(self):
        return "%s@%s" % (self.host, self.host_user)

    class Meta:
        unique_together = ('host', 'host_user')
        verbose_name_plural = "绑定"
