### Not Authorized to Access This Resource

If an authorization error similar to the one below appears:
```
/Users/scubagoggles/provider.py:463: RuntimeWarning: An exception was thrown trying to get the tenant info:
<HttpError 403 when requesting https://admin.googleapis.com/admin/directory/v1/customers/my_customer?alt=json returned "Not Authorized to access this resource/api">
```
Ensure that you consented to the following API scopes as a user with the proper [permissions to consent](#permissions) and have enabled the required [APIs and Services](#create-an-oauth-credential).