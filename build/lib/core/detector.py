# reconpro/core/detector.py
def is_method_not_allowed(response):
    return response.get("status", 200) == 405

def is_api_endpoint(response):
    headers = response.get("headers", {})
    return "application/json" in headers.get("Content-Type", "")
