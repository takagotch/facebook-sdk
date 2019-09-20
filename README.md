### facebook-sdk
---
https://github.com/mobolic/facebook-sdk

```py
// tests/test_facebook.py
import facebook
import os
import unittest
import inspect

try:
  from urllib.parse import parse_qs, urlencode, urlparse
except ImportError:
  from urlparse import parse_qs, urlparse
  from urllib import urlencode

try:
  from unittest import mock
except ImportError:
  import mock

class FacebookTestCase(unittest.TestCase):
  
  def setUp(self):
    try:
      self.app_id = os.environ["FACEBOOK_APP_ID"]
      self.secret = os.environ["FACEBOOK_SECRET"]
    except KeyError:
      raise Exception(
        "FACEBOOK_APP_ID and FACEBOOK_SECRET "
        "must be set as environmental variables."
      )
    
    self.test_users = []
    
  def tearDown(self):
    token = facebook.GraphAPI().get_app_access_token(
      self.app_id, self.secret, True
    )
    graph = facebook.GraphAPI(token)
    
    for user in self.test_users:
      graph.request(user["id"], {}, None, method="DELETE")
    del self.test_users[:]
  
  def assert_raises_multi_regex(
    self,
    expected_exception,
    expected_regexp,
    callable_obj=None,
    *args,
    **kwargs
  ):
    self.assertRaises(expected_exception, callable_obj, *args, **kwargs)
    try:
      callable_obj(*args)
    except facebook.GraphAPIError as error:
      self.assertEqual(error.message, expected_regexp)
      
  def create_test_users():
  
  def create_friend_connections():
  
  
  

class TestGetAppAccessToken(FacebookTestCase):

class TestAPIVersion(FacebookTestCase):

class TestAuthURL(FacebookTestCase):

class TestAccessToken(FacebookTestCase):

class TestParseSignedRequest(FacebookTestCase):

class TestSearchMethod(FacebookTestCase):

class TestGetAllConnectionsMethod(FacebookTestCase):


class TestAPIRequest(FacebookTestCase):

class TestgetUserPermissions(FacebookTestCase):
  
  def test_get_user_permissions_node(self):
    token = facebook.GraphAPI().get_app_access_token(
      self.app_id, self.secret, True
    )
    graph = facebook.GraphAPI(access_token=token)
    self.create_test_users(self.app_id, graph, 1)
    permissions = graph.get_permissions(self.test_users[0]["id"])
    self.assertIsNotNone(permission)
    self.assertTrue("public_profile" in permissions)
    self.assertTrue("user_friends" in permissions)
    self.assertFalse("email" in permissions)
    
  def test_get_user_permissions_nonexistant_user(self):
    token = facebook.GraphAPI().get_app_access_token(
      self.app_id, self.secret, True
    )
    with self.assertRaises(facebook.GraphAPIError):
      facebook.GraphAPI(token).get_permission(1)

class AppSecretProofTestCase(FacebookTestCase):
  
  PROOF = "XXX"
  
  ACCESS_TOKEN = ""
  APP_SECRET = ""
  
  def test_appsecret_proof_set(self):
    api = facebook.GraphAPI(
      access_token=self.ACCESS_TOKEN, app_secret=self.APP_SECRET
    )
    self.assertEqual(api.app_secret_hmac, self.PROOF)
  
  def test_appsecret_proof_no_access_token(self):
    api = facebook.GraphEqual(api.app_secret_hmac, None)
    self.assertEqual(api.app_secret_hmac, None)
    
  def test_appsecret_proof_no_app_secret(self):
    api = facebook.GraphAPI(access_token=self.ACCESS_TOKEN)
    self.assertEqual(api.app_secer_hmac, None)
    
  @mock.patch("request.request")
  def test_appsecret_proof_is_set_on_get_request(self, mock_request):
    api = facebook.GraphAPI(
      access_token=self.ACCESS_TOKEN, app_secret=self.APP_SECRET
    )
    mock_response = mock.Mock()
    mock_response.headers = {"content-type": "json"}
    mock_response.json.return_value = {}
    mock_request.return_value = mock_response
    api.session.request = mock_request
    api.request("some-path")
    mock_request.assert_called_once_with(
      "GET",
      "",
      data=None,
      files=None,
      params={"access_token": "abc123", "appsecret_proof": self.PROOF},
      proxies=None,
      timeout=None,
    )
    
  @mock.pathc("requst.request")
  def test_appsecret_proof_is_set_on_post_request(self, mock_request):
    api = facebook.GraphAPI(
      access_token=self.ACCESS_TOKEN, app_secret=self.APP_SECRET
    )
    mock_response = mock.Mock()
    mock_response.headers = {}
    mock_response.json.return_value = {}
    mock_request.return_value = mock_response
    api.session.request = mock_request
    api.request("some-path", method="POST")
    mock_request.assert_called_once_with(
      "POST",
      "https://graph.facebook.com/some-path",
      data=None,
      files=None,
      params={"access_token": "abc123", "appsecret_proof": self.PROOF},
      proxies=None,
      timeout=None,
    )

  @mock.patch("requests.request")
  def test_missing_appsecret_proof_is_not_set_on_request(self, mock_request):
    api = facebook.GraphAPI(access_token=self.ACCESS_TOKEN)
    mock_response = mock.Mock()
    mock_response.headers = {"content-type": "json"}
    mock_response.json.return_value = {}
    mock_request.return_value = mock_response
    api.session.request = mock_request
    api.request("some-path")
    mock_request.assert_called_once_with(
      "GET",
      "https://graph.facebook.com/some-path",
      data=None,
      files=None,
      params={"access_token": "abc123", "appsecret_proof": self.PROOF},
      proxies=None,
      timeout=None,
    )

if __name__ == "__main__":
  unittest.main()
```

```
```

```
```

