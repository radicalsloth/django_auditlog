import contextlib
from auditlog.context import set_actor
import time
import logging
import os
from auditlog.models import UserRequestLog


class AuditLogMiddlewareLogUserRequests:
    """Middleware for logging all user requests"""

    def __init__(self, get_response):
        self.enable_to_file_logging = False
        self.enable_to_database_logging = True
        self.url_blacklist = [
            '/login',
            '/logout',
            '/admin',
            '/static',
        ]
        self.get_response = get_response
        self.configure_file_logging()

    def log_to_database(self):
        """Creates a user view log in the database"""
        UserRequestLog.objects.create(
            user=self.request.user,
            ip_address=self.user_ip,
            request_method=self.request.method,
            full_path=self.full_path
        )

    def configure_file_logging(self):
        """Configure custom logging"""
        if self.enable_to_file_logging:
            self.log = logging.getLogger('useractions')
            handler = logging.FileHandler('/user_actions.log')
            handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
            self.log.addHandler(handler)
            self.log.setLevel(logging.INFO)

    def get_user_email(self):
        """Return the user's email, or anonymous"""
        try:
            return self.request.user.email
        except AttributeError:
            return "anonymous"

    def get_log_line(self):
        """Return the serialzied log line"""
        log_items = [
            self.user_email,
            self.user_ip,
            self.request.method,
            self.full_path,
        ]
        return " ".join([str(i) for i in log_items])

    def get_user_ip(self):
        """Returns the IP of the user from the request"""
        x_forwarded_for_header = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for_header is not None:
            return x_forwarded_for_header.split(',')[0]
        return self.request.META.get('REMOTE_ADDR')

    def populate_log_details(self):
        """Populates the log details to the class instance"""
        self.user_ip = self.get_user_ip()
        self.user_email = self.get_user_email()
        self.full_path = self.request.get_full_path()
        self.user = self.get_user_email(),

    def path_in_blacklist(self, path):
        """Determines if a particular path is in the blacklist"""
        for blacklisted_item in self.url_blacklist:
            if str(path).startswith(blacklisted_item):
                return True
        return False
    
    def write_log(self):
        """Writes the log using the determined methods"""
        if self.request.user.is_anonymous:
            # Ignore unauthenticated requests
            return
        if self.path_in_blacklist(self.full_path):
            # Ignore blacklisted paths
            return
        if str(self.request.method).lower() != "get":
            # Ignore non get methods
            return
        if self.enable_to_file_logging:
            self.log.info(self.get_log_line())
        if self.enable_to_database_logging:
            self.log_to_database()

    def __call__(self, request):
        """Middleware entrypoint"""
        self.request = request
        self.populate_log_details()
        self.write_log()
        return self.get_response(self.request)


class AuditlogMiddleware:
    """
    Middleware to couple the request's user to log items. This is accomplished by currying the
    signal receiver with the user from the request (or None if the user is not authenticated).
    """

    def __init__(self, get_response=None):
        self.get_response = get_response

    @staticmethod
    def _get_remote_addr(request):
        if request.headers.get("X-Forwarded-For"):
            # In case of proxy, set 'original' address
            remote_addr = request.headers.get("X-Forwarded-For").split(",")[0]
            # Remove port number from remote_addr
            return remote_addr.split(":")[0]
        else:
            return request.META.get("REMOTE_ADDR")

    def __call__(self, request):
        remote_addr = self._get_remote_addr(request)

        if hasattr(request, "user") and request.user.is_authenticated:
            context = set_actor(actor=request.user, remote_addr=remote_addr)
        else:
            context = contextlib.nullcontext()

        with context:
            return self.get_response(request)
