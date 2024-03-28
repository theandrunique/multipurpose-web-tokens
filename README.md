# Multipurpose Web Tokens

## Tokens Structure

```python
"""
b64(user_data) + "." + b64(payload:mwt_id) + "." + b64(hmac)

user_data: id (email)

payload - tokens purpose
"""
```
