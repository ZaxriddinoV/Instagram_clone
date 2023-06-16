from django.urls import path
from users.views import CreateUser, VerifyAPIView,GetNewVerification

urlpatterns = [
    path('signup/',CreateUser.as_view()),
    path('verify/',VerifyAPIView.as_view()),
    path('new-verify/',GetNewVerification.as_view()),
]
