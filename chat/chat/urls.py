"""chat URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path
from djangochat import views

urlpatterns = [
     path('admin/', admin.site.urls),
     path('api/forgot username/', views.ForgotUsername),
     path('api/forgot password/', views.ForgotPassword),
     path('api/change-password/', views.PasswordChanger),
     path('api/signup/', views.user_signup),
     path('api/login/', views.user_login),
     path('api/messages/', views.messages),
     path('api/chat/', views.chat),
     path('api/del_mess/', views.del_mess)
]
   