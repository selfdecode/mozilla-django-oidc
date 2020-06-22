import importlib
import warnings

try:
    from urllib.request import parse_http_list, parse_keqv_list
except ImportError:
    # python < 3
    from urllib2 import parse_http_list, parse_keqv_list

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def parse_www_authenticate_header(header):
    """
    Convert a WWW-Authentication header into a dict that can be used
    in a JSON response.
    """
    items = parse_http_list(header)
    return parse_keqv_list(items)


def import_from_settings(attr, *args):
    """
    Load an attribute from the django settings.

    :raises:
        ImproperlyConfigured
    """
    try:
        if args:
            return getattr(settings, attr, args[0])
        return getattr(settings, attr)
    except AttributeError:
        raise ImproperlyConfigured('Setting {0} not found'.format(attr))


def import_function_from_settings(attr):
    """
    Attempt to import a class from a string representation.
    """
    value = import_from_settings(attr, None)
    if not value:
        return None

    try:
        parts = value.split('.')
        module_path, class_name = '.'.join(parts[:-1]), parts[-1]
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except ImportError as e:
        msg = 'Could not import %s for settings. %s: %s.' % (
            value, e.__class__.__name__, e,
        )
        raise ImportError(msg)


def absolutify(request, path):
    """Return the absolute URL of a path."""
    return request.build_absolute_uri(path)


def is_authenticated(user):
    """return True if the user is authenticated.
    This is necessary because in Django 1.10 the `user.is_authenticated`
    stopped being a method and is now a property.
    Actually `user.is_authenticated()` actually works, thanks to a backwards
    compat trick in Django. But in Django 2.0 it will cease to work
    as a callable method.
    """

    msg = '`is_authenticated()` is going to be removed in mozilla-django-oidc v 2.x'
    warnings.warn(msg, DeprecationWarning)
    return user.is_authenticated
