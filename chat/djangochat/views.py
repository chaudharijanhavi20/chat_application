import urllib
from random import choice
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.http.response import JsonResponse, HttpResponse
from django.template import loader
from rest_framework import status
from datetime import datetime, time, timedelta, timezone
import json
from rest_framework.decorators import api_view
from django.views.decorators.csrf import csrf_exempt
import requests
from django.db import transaction
from django.db.models import Q
from uuid import uuid4
from django.utils import timezone
from rest_framework.parsers import JSONParser
from urllib3.exceptions import InsecureRequestWarning
from django.utils.html import escape
from django.core.paginator import Paginator

from djangochat.models import SignUp, Tokens, Messages, PasswordResetLogs, delete_mess, Passwords, LoginLogs, \
    PasswordHistory
from djangochat.serializers import MessageSerializer, SignUpSerializer, PasswordSerializer


def TokenChecker(Wrapped):
    def wrapper(*args, **kwargs):
        request = args[0]

        try:
            tokenval = request.META['HTTP_AUTHORIZATION'].split(' ')[1]
            userid = request.META['HTTP_AUTHORIZATION'].split(' ')[2]
        except (KeyError, IndexError):
            return HttpResponse('<h1>Unauthorized(401)</h1>', status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = SignUp.objects.get(id=userid)
        except SignUp.DoesNotExist:
            return HttpResponse('<h1>Unauthorized(401)</h1>', status=status.HTTP_401_UNAUTHORIZED)

        try:
            token = Tokens.objects.get(user=user)
        except Tokens.DoesNotExist:
            return HttpResponse('<h1>Unauthorized(401)</h1>', status=status.HTTP_401_UNAUTHORIZED)

        # VALID LOGIN
        if token.value == tokenval and token.valid_upto > timezone.now():
            return Wrapped(*args, **kwargs)

        else:
            return HttpResponse('<h1>Token Expired(401)</h1>', status=status.HTTP_401_UNAUTHORIZED)

    return wrapper



@csrf_exempt
@api_view(['POST', 'PUT'])
def user_signup(request):
    if request.method == 'PUT' or request.method == 'POST':
        data = request.data
        # print(data)

        if not data['email'] or not data['first_name'] or not data['last_name'] or not data['gender'] or not data[
            'mobile_no'] or not data['dob'] or not data['password']:
            return JsonResponse({"Message": "Couldn't get data from site"}, status=status.HTTP_204_NO_CONTENT)

        else:
            existing_email = SignUp.objects.filter(email=data['email'])
            if not existing_email:
                password = {}
                password['value'] = make_password(data['password'], salt=None, hasher='default')
                password['failed_attempt_time'] = None
                password['last_login_on'] = None
                password['last_reset_on'] = None
                password['last_reset_date'] = None
                password['last_reset_time'] = None
                password['unlocks_on'] = None
                password['is-default'] = True
                password['failed_attempt_time'] = None

                data.pop("password")
                data.pop("cPassword")

                general_serialized = SignUpSerializer(data=data)
                if general_serialized.is_valid():
                    obj = general_serialized.save()

                password['user'] = obj.id
                password_serialized = PasswordSerializer(data=password)
                if password_serialized.is_valid():
                    password_serialized.save()
            else:
                return JsonResponse({"Message": "Email Already Exists"}, status=status.HTTP_406_NOT_ACCEPTABLE)
        return JsonResponse({"Message": "Account Created Successfully"}, status=status.HTTP_201_CREATED)


    else:
        # Wrong Request method
        return JsonResponse({"Message": "Wrong Request Method"}, status=status.HTTP_400_BAD_REQUEST)



@csrf_exempt
@api_view(['POST', 'PUT'])
def user_login(request):
    if request.method == 'PUT' or request.method == 'POST':

        email = request.data.get('email')
        password = request.data.get('password')

        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

        # SAVE IP ADDRESS

        url = 'https://ipapi.co/' + ip + '/json/'

        contents = urllib.request.urlopen(url).read()

        try:
            contents = json.loads(contents)

            loginlog = LoginLogs.objects.create(
                city=contents['city'],
                country=contents['country'],
                ip=ip,
                latitude=contents['latitude'],
                longitude=contents['longitude'],
                log_date=timezone.now(),
                org=contents['org'],
                postal=contents['postal'],
                region=contents['region'],
                region_code=contents['region_code'],
                request_page='Login',
                time_zone=contents['utc_offset'],
            )

        # COULD NOT GET INFORMATION FROM CURRENT IP HENCE ISACTIVE=2
        except KeyError:
            loginlog = LoginLogs.objects.create(
                ip=ip,
                log_date=timezone.now(),
                request_page='Login',
                isactive=2
            )

        try:
            userobj = SignUp.objects.get(email=email)
            passwordobj = Passwords.objects.get(user=userobj.id)

            loginlog.user = userobj
            ind_serializer = SignUpSerializer(userobj)

            if check_password(password, passwordobj.value):

                if passwordobj.unlocks_on:
                    if passwordobj.unlocks_on > timezone.now():
                        remaining_time = (passwordobj.unlocks_on - timezone.now()).seconds
                        message = 'Try again later in ' + str(remaining_time // 60) + ' minutes ' + str(
                            remaining_time % 60) + ' seconds.'
                        loginlog.login_status = False
                        loginlog.cause = 'Acccount Temporarily Locked Out'
                        loginlog.save()
                        return JsonResponse(
                            {'message': message, 'success': False, 'login_id': userobj.user_id, 'auth_token': '',
                             'auth_id': ''}, status=status.HTTP_429_TOO_MANY_REQUESTS)

                try:
                    Tokens.objects.filter(user=userobj).delete()
                except Tokens.DoesNotExist:
                    pass

                token_code = str(uuid4())
                Tokens.objects.create(value=token_code, valid_upto=timezone.now() + timedelta(minutes=40), user=userobj)

                passwordobj.failed_attempts = 0
                passwordobj.failed_attempt_time = None
                passwordobj.unlocks_on = None
                Lastlogin = passwordobj.last_login_on
                passwordobj.last_login_on = timezone.now()
                passwordobj.save()

                message = 'Welcome! ' + str(userobj.first_name)


                ChangeRequired = passwordobj.isdefault or (
                        (passwordobj.last_reset_date + timedelta(days=60)) <= datetime.today().date())

                loginlog.login_status = True
                loginlog.save()

                o = ind_serializer.data
                o['auth_token'] = token_code
                o['message'] = message
                o['success'] = Lastlogin
                o['message'] = True
                o['change_required'] = ChangeRequired
                # LOGIN ACCEPTED RESPONSE SEND ALL OTHER NECESSARY INFORMATION ALONG WITH THIS
                return JsonResponse(o, status=status.HTTP_202_ACCEPTED, safe=False)

            else:
                passwordobj.failed_attempts += 1
                passwordobj.failed_attempt_time = timezone.now()

                if passwordobj.failed_attempts >= 5:
                    if passwordobj.unlocks_on == None:
                        passwordobj.unlocks_on = timezone.now() + timedelta(minutes=20)
                        loginlog.cause = 'Incorrect Password Entered, attempt: 5 Account Locked!'
                        message = 'Too many unsuccessful attempts, Your Account has been Temporarily Blocked. Try again in 20 minutes.'

                    elif passwordobj.unlocks_on < timezone.now():
                        passwordobj.failed_attempts = 1
                        passwordobj.failed_attempt_time = timezone.now()
                        passwordobj.unlocks_on = None
                        loginlog.cause = 'Incorrect Password Entered, attempt: ' + str(passwordobj.failed_attempts)
                        message = 'Invalid Credentials. Please check Username or Password. Unsuccessful attempts: ' + str(
                            passwordobj.failed_attempts) + ', After ' + str(
                            5 - passwordobj.failed_attempts) + ' more attempts, account will be temporarily blocked.'

                    else:
                        remaining_time = (passwordobj.unlocks_on - timezone.now()).seconds
                        loginlog.cause = 'Acccount Temporarily Locked Out'
                        message = 'Try again later in ' + str(remaining_time // 60) + ' minutes ' + str(
                            remaining_time % 60) + ' seconds.'

                    passwordobj.save()
                    loginlog.login_status = False
                    loginlog.save()
                    return JsonResponse({
                        'message': message,
                        'success': False,
                        'loginId': 0,
                        'auth_token': '',
                        'auth_id': ''
                    }, status=status.HTTP_429_TOO_MANY_REQUESTS)

                else:
                    loginlog.cause = 'Incorrect Password Entered, attempt: ' + str(passwordobj.failed_attempts)
                    loginlog.login_status = False
                    loginlog.save()
                    message = 'Invalid Credentials. Please check Username or Password. Unsuccessful attempts: ' + str(
                        passwordobj.failed_attempts) + ', After ' + str(
                        5 - passwordobj.failed_attempts) + ' more attempts, account will be temporarily blocked.'
                passwordobj.save()
                return JsonResponse({'message': message, 'success': False, 'login_id': 0}, status=status.HTTP_200_OK)

        except SignUp.DoesNotExist:
            loginlog.cause = 'Invalid Login'
            loginlog.login_status = False
            loginlog.save()
            return JsonResponse({"Message": "Invalid Login"}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def PasswordChanger(request):
    newpassword = request.data.get('password')

    if request.GET.get('type') == 'forgot':
        email = request.data.get('email')
        if newpassword:
            userobj = SignUp.objects.get(email=email)
            paswordobj = Passwords.objects.get(user=userobj)
            otp = request.data.get('otp')
            try:
                otpobj = PasswordResetLogs.objects.get(user=userobj, isactive=1)

                if otpobj.forgot_token != str(otp):
                    if otpobj.attempts >= 3:
                        return JsonResponse(
                            {'message': 'Too Many Incorrect OTPs entered, Please request a new one', 'success': False},
                            status=status.HTTP_429_TOO_MANY_REQUESTS)
                    else:
                        otpobj.attempts += 1
                        otpobj.save()
                        return JsonResponse({'message': 'Wrong OTP Entered, Try Again!', 'success': False})

                if otpobj.expires_on > timezone.now():
                    if paswordobj.value == newpassword:
                        return JsonResponse(
                            {'message': 'New Password cannot be the same as old password', 'success': False})
                    else:
                        paswordobj.value = escape(newpassword)
                        paswordobj.last_reset_on = timezone.now()
                        paswordobj.last_reset_date = datetime.today().date()
                        paswordobj.last_reset_time = timezone.now().time()
                        paswordobj.passwords_changed += 1
                        paswordobj.isdefault = False

                        PasswordHistory.objects.create(
                            user=userobj,
                            changed_on=timezone.now(),
                            new_password=escape(newpassword),
                            old_password=paswordobj.value
                        )

                        paswordobj.save()
                        otpobj.isactive = 0
                        otpobj.save()
                        return JsonResponse({'message': 'Password Changed Successfully', 'success': True},
                                            status=status.HTTP_202_ACCEPTED)
                else:
                    return JsonResponse({'message': 'OTP Expired', 'success': False})

            except PasswordResetLogs.DoesNotExist:
                return JsonResponse(
                    {'message': 'Invalid Request, No Active OTP associated to user. Please Request a New one',
                     'success': False})

        else:
            return JsonResponse({'message': 'Invalid Request', 'success': False}, status=status.HTTP_400_BAD_REQUEST)

    if request.GET.get('type') == 'login':
        # id = request.data.get('id')
        email = request.data.get('email')

        if TokenChecker(request, email) == True:
            if newpassword:
                userobj = SignUp.objects.get(email=email)
                paswordobj = Passwords.objects.get(password=userobj)
                if paswordobj.value == newpassword:
                    return JsonResponse(
                        {'message': 'New Password cannot be the same as old password', 'success': False})
                else:
                    paswordobj.value = escape(newpassword)
                    paswordobj.last_reset_on = timezone.now()
                    paswordobj.last_reset_date = datetime.today().date()
                    paswordobj.last_reset_time = timezone.now().time()
                    paswordobj.passwords_changed += 1
                    paswordobj.is_default = False

                    PasswordHistory.objects.create(
                        user=userobj,
                        changed_on=timezone.now(),
                        new_password=escape(newpassword),
                        old_password=paswordobj.value
                    )

                    paswordobj.save()
                    return JsonResponse({'message': 'Password Changed Successfully', 'success': True},
                                        status=status.HTTP_202_ACCEPTED)
            else:
                return JsonResponse({'message': 'Invalid Request', 'success': False},
                                    status=status.HTTP_400_BAD_REQUEST)

        else:
            return TokenChecker(request, id)


@api_view(['POST'])
def ForgotUsername(request):
    email = request.data.get('email')

    try:
        # ASSUMING THAT EMAIL IS NOT UNIQUE, IF IT IS UNIQUE PLEASE USE GET INSTEAD OF FILTERS
        associated_users = SignUp.objects.filter(email=email)
        emails = ['Username: "' + x.emp_code + '", Name - ' + x.name for x in associated_users]

        html_message = loader.render_to_string(
            'ForgotUsername.html',
            {
                'usernames': emails,
            }
        )

        send_mail('Digital SIL: Username Recovery Request. Do-not-reply', 'Text Alternative', settings.EMAIL_HOST_USER,
                  [email], html_message=html_message)

        return JsonResponse({'message': 'Associated Usernames Sent to your Email Address', 'success': True})
    except:
        return JsonResponse({'message': 'Something Went Wrong please contact site administrator', 'success': False})


@api_view(['POST'])
def ForgotPassword(request):
    email = request.data.get('email')

    try:
        userobj = SignUp.objects.get(email=email)
        otp = ''.join(choice('0123456789') for i in range(6))
        email = userobj.email

        if PasswordResetLogs.objects.filter(user=userobj, request_date=datetime.today().date()).count() >= 5:
            return JsonResponse(
                {'message': "You've Exceeded Maximum OTP requests for today. Try Again Tomorrow", 'success': False},
                status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            PasswordResetLogs.objects.filter(user=userobj).update(isactive=0)
            PasswordResetLogs.objects.create(
                user=userobj,
                isactive=1,
                request_date=datetime.today().date(),
                expires_on=timezone.now() + timedelta(minutes=10),
                forgot_token=otp
            )

            html_message = loader.render_to_string(
                'ForgotPassword.html',
                {
                    'username': userobj.email,
                    'name': userobj.first_name,
                    'OTP': otp,
                }
            )

            send_mail('chat: Password Recovery Request. Do-not-reply',
                      'Text Alternative',
                      'js1910492@gmail.com',
                      [email],
                      html_message=html_message
                      )

            return JsonResponse({'message': 'OTP Sent to your Associated Email.', 'success': True})

    except SignUp.DoesNotExist:
        return JsonResponse({'message': 'Username Incorrect. Please enter your proper username', 'success': False})

    except PasswordResetLogs.DoesNotExist:
        return JsonResponse({'message': 'OTP Invalid or Expired', 'success': False})


def messages(request, sender, reciever):
    if request.method == 'GET':
        messages = Messages.objects.filter(sender_name=sender, receiver_name=reciever, seen=False)
        serializer = MessageSerializer(messages, many=True, context={'request': request})
        for message in messages:
            message.seen = True
            message.save()
        return JsonResponse(serializer.data, safe=False)

    elif request.method == "POST":
        data = JSONParser().parse(request)
        serializer = MessageSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=201)
        return JsonResponse(serializer.errors, status=400)


def chat(request, sender, reciever):
    list_message=[]
    mess = Messages.objects.filter(sender_name=sender, receiver_name=reciever, seen=False)
    serializer = MessageSerializer(messages, many=True, context={'request': request})
    for message in mess:
        if delete_mess.objects.filter(sender_id=sender, reciever_id=reciever, message=message):
            pass
        else:
            list_message.append(message)
    print(list_message)
    return JsonResponse(serializer.data, safe=False)


def del_mess(request):
    data=request.data
    if Messages(sender_id=data['sender_id'], receiver_id=data['reciever_id'], message_id=data['message']).exists:
        delete_mess(sender_id=data['sender_id'], receiver_id=data['reciever_id'], message_id=data['message']).save()
