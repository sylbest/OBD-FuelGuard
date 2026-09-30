<?php
// config.php - Supabase Configuration

// Your Supabase Credentials
define('SUPABASE_URL', 'https://ccfbriojkjmznqrujjis.supabase.co');
define('SUPABASE_PUBLISHABLE_KEY', 'sb_publishable_FKO7lAAtyuONsZCEE13Q5A_1TiXv-bs');
define('SUPABASE_SECRET_KEY', 'sb_secret_JM9CRYFyergappWI8uQ7yg_Jb6TCfa0');
define('SUPABASE_JWKS_URL', 'https://ccfbriojkjmznqrujjis.supabase.co/auth/v1/.well-known/jwks.json');

// Use the secret key for backend API calls (more secure than publishable key)
define('SUPABASE_KEY', SUPABASE_SECRET_KEY);

// API Endpoints
define('SUPABASE_API_URL', SUPABASE_URL . '/rest/v1');

// Headers for API requests
function getHeaders() {
    return [
        'Content-Type: application/json',
        'apikey: ' . SUPABASE_KEY,
        'Authorization: Bearer ' . SUPABASE_KEY,
        'Prefer: return=representation'
    ];
}

// Database Connection Status
$dbConnected = false;
try {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, SUPABASE_API_URL . '/?select=count');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'apikey: ' . SUPABASE_KEY,
        'Authorization: Bearer ' . SUPABASE_KEY
    ]);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $dbConnected = ($httpCode === 200 || $httpCode === 206);
} catch (Exception $e) {
    $dbConnected = false;
}
?>