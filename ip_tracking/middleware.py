from django.utils import timezone
from django.http import HttpResponseForbidden
from ip_tracking.models import RequestLog, BlockedIP

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Block blacklisted IPs (Task 1)
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Forbidden")

        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            timestamp=timezone.now()
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')
