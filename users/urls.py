from django.urls import path
from users.views import CreateUser, VerifyAPIView, GetNewVerification, ChangeUserIndormationView, ChangeUserPhotoView, \
    LoginView

urlpatterns = [
    path("login/", LoginView.as_view()),
    path('signup/',CreateUser.as_view()),
    path('verify/',VerifyAPIView.as_view()),
    path('new-verify/',GetNewVerification.as_view()),
    path('change-user/',ChangeUserIndormationView.as_view()),
    path('change-user-photo/',ChangeUserPhotoView.as_view()),
]
