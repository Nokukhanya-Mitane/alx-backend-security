from django.core.cache import cache
from ipgeolocation import IpGeolocationAPI
from ip_tracking.models import RequestLog, BlockedIP

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = IpGeolocationAPI()

    def __call__(self, request):
        ip = self.get_client_ip(request)

        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Forbidden")

        geo_data = cache.get(ip)
        if not geo_data:
            geo_data = self.geo.get_geolocation(ip)
            cache.set(ip, geo_data, 60 * 60 * 24)

        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=geo_data.get('country_name'),
            city=geo_data.get('city')
        )

        return self.get_response(request)
