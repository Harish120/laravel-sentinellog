<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confirm Login Location</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f7fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.1); padding: 40px; max-width: 460px; width: 100%; }
        h2 { color: #2b6cb0; margin: 0 0 8px; }
        p { color: #4a5568; line-height: 1.6; }
        .meta { background: #ebf8ff; border-left: 4px solid #2b6cb0; padding: 12px 16px; border-radius: 4px; margin: 20px 0; font-size: 14px; color: #2c5282; }
        .btn-confirm { background: #2b6cb0; color: white; border: none; padding: 12px 28px; border-radius: 6px; font-size: 16px; cursor: pointer; width: 100%; }
        .btn-confirm:hover { background: #2c5282; }
        .cancel { display: block; text-align: center; margin-top: 14px; color: #718096; font-size: 14px; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Confirm This Login?</h2>
        <p>You received this link because a login was detected from a new location.</p>
        <div class="meta">
            <strong>Location:</strong> {{ $city }}, {{ $country }}<br>
            <strong>IP Address:</strong> {{ $ip }}
        </div>
        <p>Click confirm to trust this location. If this was <strong>not</strong> you, close this page and use the deny link in the email instead.</p>
        <form method="POST" action="{{ $postUrl }}">
            @csrf
            <button type="submit" class="btn-confirm">Yes, this was me</button>
        </form>
        <a href="/" class="cancel">Cancel</a>
    </div>
</body>
</html>
