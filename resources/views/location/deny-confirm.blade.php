<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deny Login — Security Alert</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f7fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.1); padding: 40px; max-width: 460px; width: 100%; }
        h2 { color: #e53e3e; margin: 0 0 8px; }
        p { color: #4a5568; line-height: 1.6; }
        .meta { background: #fff5f5; border-left: 4px solid #e53e3e; padding: 12px 16px; border-radius: 4px; margin: 20px 0; font-size: 14px; color: #742a2a; }
        .btn-deny { background: #e53e3e; color: white; border: none; padding: 12px 28px; border-radius: 6px; font-size: 16px; cursor: pointer; width: 100%; }
        .btn-deny:hover { background: #c53030; }
        .cancel { display: block; text-align: center; margin-top: 14px; color: #718096; font-size: 14px; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Deny This Login?</h2>
        <p>Someone logged in to your account from a location you have not used before.</p>
        <div class="meta">
            <strong>Location:</strong> {{ $city }}, {{ $country }}<br>
            <strong>IP Address:</strong> {{ $ip }}
        </div>
        <p>Confirming will <strong>immediately revoke that session</strong> and log a security event. If this was you, click Cancel instead.</p>
        <form method="POST" action="{{ $postUrl }}">
            @csrf
            <button type="submit" class="btn-deny">Yes, deny this login</button>
        </form>
        <a href="/" class="cancel">Cancel — this was me</a>
    </div>
</body>
</html>
