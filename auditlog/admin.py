from django.contrib import admin
from django.contrib.auth import get_user_model

from auditlog.filters import ResourceTypeFilter
from auditlog.mixins import LogEntryAdminMixin, LogBaseAdminMixin
from auditlog.models import LogEntry, UserRequestLog


class LogEntryAdmin(admin.ModelAdmin, LogBaseAdminMixin, LogEntryAdminMixin):
    list_select_related = ["content_type", "actor"]
    list_display = ["created", "resource_url", "action", "msg_short", "user_url"]
    search_fields = [
        "timestamp",
        "object_repr",
        "changes",
        "actor__first_name",
        "actor__last_name",
        f"actor__{get_user_model().USERNAME_FIELD}",
    ]
    list_filter = ["action", ResourceTypeFilter]
    readonly_fields = ["created", "resource_url", "action", "user_url", "msg"]
    fieldsets = [
        (None, {"fields": ["created", "user_url", "resource_url"]}),
        ("Changes", {"fields": ["action", "msg"]}),
    ]
    actions = ['export_as_csv']

    def has_add_permission(self, request):
        # As audit admin doesn't allow log creation from admin
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(LogEntry, LogEntryAdmin)


@admin.register(UserRequestLog)
class UserRequestLogAdmin(admin.ModelAdmin, LogBaseAdminMixin):
    """Admin for user request logs"""
    list_display = ['user', 'full_path', 'created_on', 'ip_address',]
    list_filter = ['user', 'created_on', 'ip_address']
    actions = ['export_as_csv']
