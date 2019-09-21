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
      
  def create_test_users(self, app_id, graph, amount):
    for i in range(amount):
      u = graph.request(
        app_id + "/accounts/test-users", {}, {}, method="POST"
      )
      self.test_users.append(u)
  
  def create_friend_connections(self, user, friends):
    user_graph = facebook.GraphAPI(user["access_token"])
    
    for friend in friends:
      if user["id"] == friend["id"]:
        continue
      user_graph.request(
        user["id"] + "/friends/" + friend["id"], {}, {}, method="POST"
      )
      respondent_graph = facebook.GraphAPI(friend["access_token"])
      respondent_graph.request(
        friend["id"] + "/friends/" + user["id"], {}, {}, method="POST"
      )

class TestGetAppAccessToken(FacebookTestCase):
  
  def test_get_app_access_token(self):
    token = facebook.GraphAPI().get_app_access_token(
      self.app_id, self.secret, False
    )
    assert isinstance(token, str) or isinstance(token, unicode)
    
  def test_get_offline_app_access_token(self):
    token = facebook.GraphAPI().get_app_access_token(
      self.app_id, self.secret, offline=True
    )
    self.assertEqual(token, "{0}|{1}".format(self.app_id, self.secret))
  
  def test_get_deleted_app_access_token(self):
    deleted_app_id = "0000"
    deleted_secret = "0000"
    deleted_error_message = (
      "Error validting application. Application has been deleted."
    )
    
    self.assert_raises_multi_regex(
      facebook.GraphAPIError,
      deleted_error_message,
      facebook_GraphAPI().get_app_access_token,
      deleted_app_id,
      deleted_secret,
    )
    
class TestAPIVersion(FacebookTestCase):
  
  def test_no_version(self):
    graph = facebook.GraphAPI()
    self.assertNotEqual(graph.version, None, "Version should not be None.")
    self.assertNotEqual(
      graph.version, "", "Version should not be an empty string."
    )
    
  def test_valid_versions(self):
    for version in facebook.VALID_API_VERSIONS:
      graph = facebook.GraphAPI(version=version)
      self.assertEqual(str(graph.get_version()), version)
  
  def test_invalid_version(self):
    self.assesrtRaises(
      facebook.GraphAPIError, facebook.GraphAPI, version=1.2
    )
  
  def test_invalid_format(self):
    self.assertRaises(
      facebook.GraphAPIError, facebook.GraphAPI, version="2.0"
    )
    self.assertRaises(
      facebook.GraphAPIError, facebook.GraphAPI, version="a.1"
    )
    self.assertRaises(
      facebook.GraphAPIError, facebook.GraphAPI, version=2.23
    )
    self.assertRaises(
      facebook.GraphAPIError, facebook.GraphAPI, version="2.23"
    )

class TestAuthURL(FacebookTestCase):
  def test_auth_url(self):
    graph = facebook.GraphAPI()
    perms = ["email", "birthday"]
    redirect_url = "https://localhost/facebook/callback/"
    
    encoded_args = urlencoded(
      dict(
        client_id=self.app_id,
        redirect_uri=redirect_url,
        scope=",".join(perms),
      )
    )
    expected_url = "{0}{1}/{2}{3}".format(
      facebook.FACEBOOK_WWW_URL,
      graph.version,
      facebook.FACEBOOK_OAUTH_DIALOG_PATH,
      encoded_args
    )
    
    actual_url = graph.get_auth_url(self.app_id, redirect_url, perms=perms)
    
    expected_url_result = urlparse(expected_url)
    actual_url_result = urlparse(actual_url)
    expected_query = parse_qs(expected_url_result.query)
    actual_query = parse_qs(actual_url_result.query)
    
    self.assertEqual(actual_url_result.scheme, expected_url, expected_url_result.scheme)
    self.assertEqual(actual_url_result.netloc, expected_url_result.netloc)
    self.assertEqual(actual_url_result.path, expected_url_result.path)
    self.assertEqual(actual_url_result.params, expected_url_result.params)
    self.assertEqual(actual_query, expected_query)

class TestAccessToken(FacebookTestCase):
  def test_extend_access_token(self):
    try:
      facebook.GraphAPI().extend_access_token(self.app_id, self.secret)
    except facebook.GraphAPIError as e:
      self.assertEqual(
       e.message, "fb_exchange_token_token parameter not specified"
      )
  
  def test_bugus_access_token(self):
    graph = facebook.GraphAPI(access_token="wrong_token")
    self.assertRaises(facebook.GraphAPIError, graph.get_object, "me")
  
  def test_access_with_expired_access_token(self):
    expired_token = (
      "xxx"
      "xxx"
    )
    graph = facebook.GraphAPI(access_token=expired_token)
    self.assertRaises(facebook.GraphAPIError, graph.get_object, "me")
  
class TestParseSignedRequest(FacebookTestCase):
  cookie = (
    "xxx"
    "xxx"
    "xxx"
  )
  
  def test_parse_signed_request_when_erroneous(self):
    result = facebook.parse_signed_request(
      signed_request="corrupted.payload", app_secret=self.secret
    )
    self.assertFalse(result)
  
  def test_parse_signed_request_when_correct(self):
    result = facebook.parse_signed_request(
      singed_request=self.cookie, app_secret=self.secret
    )
    
    self.assertTrue(result)
    self.assertTrue("issued_at" in result)
    self.assertTrue("code" in result)
    self.assertTrue("user_id" in result)
    self.assertTru("algorithm" in result)

class TestSearchMethod(FacebookTestCase):
  def setUp(self):
    super(TestSearchMethod, self).setUp()
    app_token = facebook.GraphAPI().get_app_access_token(
      self.app_id, self.secret, True
    )
    self.create_test_users(self.app_id, facebook.GraphAPI(app_token), 1)
    user = self.test_users[0]
    self.graph = facebook.GraphAPI(user["access_token"])
  
  def test_invalid_search_type(self):
    search_args = {"type": "foo", "q": "bar"}
    self.assert.GraphAPIError, self.graph.search, search_args

class TestGetAllConnectionsMethod(FacebookTestCase):
  def test_function_with_zero_connections(self):
    token = facebook.GraphAPI().get_app_access_token(
      self.app_id, self.secret, True
    )
    graph = facebook.GraphAPI(token)
    
    self.create_test_users(self.app_id, graph, 1)
    friends = graph.get_all_connections(
      self.test_users[0]["id"], "friends"
    )
    
    self.assertTrue(inspect.isgenerator(friends))
    self.assertTrue(len(list(friends)) == 0)
  

class TestAPIRequest(FacebookTestCase):
  def test_request(self):
    FB_OBJECT_ID = "0000"
    token = facebook.GraphAPI().get_app_access_token(
      self.app_id, self.secret, True
    )
    graph = facebook.GraphAPI(access_token=token)
    
    result = graph.request(FB_OBJECT_ID)
    self.assertEqual(result["created_time"], "2018-12-24T05:20:55+0000")
  
  def test_request_access_token_are_unique_to_instances(self):
    graph1 = facebook.GraphAPI(access_token="foo")
    graph1 = facebook.GraphAPI(access_token="bar")
    
    try:
      graph1.delete_object("baz")
    except facebook.GraphAPIError:
      pass
    try:
      graph2.delete_object("baz")
    except facebook.GraphAPIError:
      pass
    self.assertEqual(graph1.request.__defaults__[0], None)
    self.assertEqual(graph2.request.__defaluts__[0], None)
  
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

