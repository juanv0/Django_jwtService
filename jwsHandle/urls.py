from .views import JwsAPIView,JsonApiView
from django.urls import path

# just two uris
urlpatterns = [
    path("signJson/", JwsAPIView.as_view(), name="Sign_Json"),
    path("unsignJson/", JsonApiView.as_view(), name="Unsign_JWS")
]
