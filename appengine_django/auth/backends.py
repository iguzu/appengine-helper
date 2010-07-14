from django.contrib.auth.models import User
import logging


class ModelBackend(object):
    """
    Authenticates against django.contrib.auth.models.User.
    """
    # TODO: Model, login attribute name and password attribute name should be
    # configurable.
    def authenticate(self, username=None, password=None):
        user = User.get_by_key_name(username)
        if user and user.check_password(password):
            return user

    def get_group_permissions(self, user_obj):
        """
        Returns a set of permission strings that this user has through his/her
        groups.
        """
        return ()

    def get_all_permissions(self, user_obj):
        return ()

    def has_perm(self, user_obj, perm):
        return ''

    def has_module_perms(self, user_obj, app_label):
        """
        Returns True if user_obj has any permissions in the given app_label.
        """
        return False

    def get_user(self, user_id):
        return User.get_by_key_name(user_id)
