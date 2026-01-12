from django.http import JsonResponse
from ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', block=True)
def anonymous_sensitive_view(request):
    return JsonResponse({'status': 'ok'})

@ratelimit(key='user', rate='10/m', block=True)
def authenticated_sensitive_view(request):
    return JsonResponse({'status': 'ok'})
