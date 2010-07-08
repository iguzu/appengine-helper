# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import datetime
from django.utils.hashcompat import md5_constructor, sha_constructor


"""
App Engine compatible models for the Django authentication framework.
"""

from django.core import mail
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.encoding import smart_str
import urllib

from django.db.models.manager import EmptyManager
from google.appengine.ext import db
from appengine_django.models import BaseModel
    
UNUSABLE_PASSWORD = '!' # This will never be a valid hash

def get_hexdigest(algorithm, salt, raw_password):
    """
    Returns a string of the hexdigest of the given plaintext password and salt
    using the given algorithm ('md5', 'sha1' or 'crypt').
    """
    raw_password, salt = smart_str(raw_password), smart_str(salt)
    if algorithm == 'crypt':
        try:
            import crypt
        except ImportError:
            raise ValueError('"crypt" password algorithm not supported in this environment')
        return crypt.crypt(raw_password, salt)

    if algorithm == 'md5':
        return md5_constructor(salt + raw_password).hexdigest()
    elif algorithm == 'sha1':
        return sha_constructor(salt + raw_password).hexdigest()
    raise ValueError("Got unknown password algorithm type in password.")

def check_password(raw_password, enc_password):
    """
    Returns a boolean of whether the raw_password was correct. Handles
    encryption formats behind the scenes.
    """
    algo, salt, hsh = enc_password.split('$')
    return hsh == get_hexdigest(algo, salt, raw_password)


class UserManager(models.Manager):
    def create_user(self, username, email, password=None):
        """
        Creates and saves a User with the given username, e-mail and password.
        """

        now = datetime.datetime.now()
        
        # Normalize the address by lowercasing the domain part of the email
        # address.
        try:
            email_name, domain_part = email.strip().split('@', 1)
        except ValueError:
            pass
        else:
            email = '@'.join([email_name, domain_part.lower()])

        user = self.model(key_name=username,username=username, email=email, is_staff=False,
                         is_active=True, is_superuser=False, last_login=now,
                         date_joined=now)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save()
        return user

    def create_superuser(self, username, email, password):
        u = self.create_user(username, email, password)
        u.is_staff = True
        u.is_active = True
        u.is_superuser = True
        u.save()
        return u

    def make_random_password(self, length=10, allowed_chars='abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'):
        "Generates a random password with the given length and given allowed_chars"
        # Note that default value of allowed_chars does not have "I" or letters
        # that look like it -- just to avoid confusion.
        from random import choice
        return ''.join([choice(allowed_chars) for i in range(length)])



class User(BaseModel):
    """A model with the same attributes and methods as a Django user model.

    The model has two additions. The first addition is a 'user' attribute which
    references a App Engine user. The second is the 'get_djangouser_for_user'
    classmethod that should be used to retrieve a DjangoUser instance from a App
    Engine user object.
    """
    username = db.StringProperty(required=True)
    first_name = db.StringProperty()
    last_name = db.StringProperty()
    email = db.EmailProperty()
    password = db.StringProperty()
    is_staff = db.BooleanProperty(default=False, required=True)
    is_active = db.BooleanProperty(default=True, required=True)
    is_superuser = db.BooleanProperty(default=False, required=True)
    last_login = db.DateTimeProperty(auto_now_add=True, required=True)
    date_joined = db.DateTimeProperty(auto_now_add=True, required=True)
    address = db.PostalAddressProperty(required=False)
    country = db.StringProperty()
    
    
    groups = EmptyManager()
    user_permissions = EmptyManager()
    objects = UserManager()

    def __init__(self,*args,**kwargs):
        super(User,self).__init__(*args,**kwargs)
        self.id = str(self.key())

    def __unicode__(self):
        return self.username

    def __str__(self):
        return unicode(self).encode('utf-8')

    def set_password(self, raw_password):
        import random
        algo = 'sha1'
        salt = get_hexdigest(algo, str(random.random()), str(random.random()))[:5]
        hsh = get_hexdigest(algo, salt, raw_password)
        self.password = '%s$%s$%s' % (algo, salt, hsh)

    def check_password(self, raw_password):
        """
        Returns a boolean of whether the raw_password was correct. Handles
        encryption formats behind the scenes.
        """
        # Backwards-compatibility check. Older passwords won't include the
        # algorithm or salt.
        if '$' not in self.password:
            is_correct = (self.password == get_hexdigest('md5', '', raw_password))
            if is_correct:
                # Convert the password to the new, more secure format.
                self.set_password(raw_password)
                self.save()
            return is_correct
        return check_password(raw_password, self.password)

    def set_unusable_password(self):
        # Sets a value that will never be a valid hash
        self.password = UNUSABLE_PASSWORD

    def has_usable_password(self):
        return self.password != UNUSABLE_PASSWORD

    def get_group_permissions(self):
        return self.user_permissions

    def get_all_permissions(self):
        return self.user_permissions

    def has_perm(self, perm):
        return False

    def has_perms(self, perm_list):
        return False

    def has_module_perms(self, module):
        return False

    def get_and_delete_messages(self):
        """Gets and deletes messages for this user"""
        msgs = []
        for msg in self.message_set:
            msgs.append(msg)
            msg.delete()
        return msgs

    def is_anonymous(self):
        """Always return False"""
        return False

    def is_authenticated(self):
        """Always return True"""
        return True

    def get_absolute_url(self):
        return "/users/%s/" % urllib.quote(smart_str(self.username))

    def get_full_name(self):
        full_name = u'%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def email_user(self, subject, message, from_email):
        """Sends an email to this user.

        According to the App Engine email API the from_email must be the
        email address of a registered administrator for the application.
        """
        mail.send_mail(subject,
                       message,
                       from_email,
                       [self.email])

    def get_profile(self):
        """
        Returns site-specific profile for this user. Raises
        SiteProfileNotAvailable if this site does not allow profiles.

        When using the App Engine authentication framework, users are created
        automatically.
        """
        from django.contrib.auth.models import SiteProfileNotAvailable
        if not hasattr(self, '_profile_cache'):
            from django.conf import settings
            if not hasattr(settings, "AUTH_PROFILE_MODULE"):
                raise SiteProfileNotAvailable
            try:
                app_label, model_name = settings.AUTH_PROFILE_MODULE.split('.')
                model = models.get_model(app_label, model_name)
                self._profile_cache = model.all().filter("user =", self).get()
                if not self._profile_cache:
                    raise model.DoesNotExist
            except (ImportError, ImproperlyConfigured):
                raise SiteProfileNotAvailable
        return self._profile_cache


class Group(BaseModel):
    """Group model not fully implemented yet."""
    # TODO: Implement this model, requires contenttypes
    name = db.StringProperty()
    permissions = EmptyManager()


class Message(BaseModel):
    """User message model"""
    user = db.ReferenceProperty(User)
    message = db.TextProperty()


class Permission(BaseModel):
    """Permission model not fully implemented yet."""
    # TODO: Implement this model, requires contenttypes
    name = db.StringProperty()
