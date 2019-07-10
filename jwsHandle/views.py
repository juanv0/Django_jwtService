from django.views.generic import View
from django.http import HttpResponse
from .firma_jws import sign_json, unsign_json
import json


class JwsAPIView(View):
    body = ""

    # i use to make cumstom action for verbs (post, get) this way 
    def get(self, request, *args, **kwargs):
        body = {"Response": "You need to post some json"}
        return HttpResponse(json.dumps(body), content_type="application/json")

    def post(self, request, *args, **kwargs):

        body = sign_json(request.body)
        return HttpResponse(body, content_type='application/json')


class JsonApiView(View):
    body = ""

    def get(self, request, *args, **kwargs):
        body = {"Response": "You need to post some json with jwt"}
        return HttpResponse(json.dumps(body), content_type="application/json")

    def post(self, request, *args, **kwargs):
        body = unsign_json(request.body)
        return HttpResponse(body, content_type="application/json")
