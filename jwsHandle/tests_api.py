from django.test import TestCase, Client
from .firma_jws import unsign_json, sign_json


class JWSTestCase(TestCase):
    #Testing get method, just for learning
    def test_JsonToJWSGetTest(self):
        #json in bytes
        json_test_get = b'{"Response": "You need to post some json"}'
        #client for making the http get
        client = Client()
        json_get = client.get("/signJson/")
        #to assert the thow bytes type
        self.assertEqual(json_get.content, json_test_get)

    def test_jsw(self):
        json_to_sign = '{"some", "json"}'
        client = Client()
        response = client.post("/signJson/", json_to_sign, content_type="application/json")
        #this function returns a string, no need for decode
        unsign=unsign_json(response.content)
        self.assertEqual(unsign, json_to_sign)

    def test_JWSToJsonTest(self):
        json_test_get = b'{"Response": "You need to post some json with jwt"}'
        client = Client()
        json_get = client.get("/unsignJson/")
        self.assertEqual(json_get.content, json_test_get)