<?php
date_default_timezone_set('Asia/Kolkata'); // Set the timezone to Indian Standard Time

function logMessage($message) {
    $timestamp = date('Y-m-d H:i:s'); // Get the current date and time
    file_put_contents('log.txt', "$timestamp - $message\n", FILE_APPEND); // Append the message to log.txt
}

function logIP($ipAddress, $userAgent) {
    $ipLog = 'IP.json';
    $ipData = file_exists($ipLog) ? json_decode(file_get_contents($ipLog), true) : array();
    if (!isset($ipData[$ipAddress])) {
        $ipData[$ipAddress] = array('count' => 0, 'userAgents' => array(), 'blocked' => false, 'lastAttempt' => null, 'lastUserAgent' => null);
    }
    $ipData[$ipAddress]['count']++;
    $ipData[$ipAddress]['lastAttempt'] = date('Y-m-d H:i:s');
    $ipData[$ipAddress]['lastUserAgent'] = $userAgent;
    if (!in_array($userAgent, $ipData[$ipAddress]['userAgents'])) {
        $ipData[$ipAddress]['userAgents'][] = $userAgent;
    }
    if ($ipData[$ipAddress]['count'] > 500) {
        $ipData[$ipAddress]['blocked'] = true;
    }
    file_put_contents($ipLog, json_encode($ipData, JSON_PRETTY_PRINT));
        return $ipData[$ipAddress];
    }

function unbanIP($ipAddress) {
    $ipLog = 'IP.json';
    $ipData = file_exists($ipLog) ? json_decode(file_get_contents($ipLog), true) : array();
    if (!isset($ipData[$ipAddress])) {
        return 'IP not found';
    }
    $ipData[$ipAddress]['count'] = 0;
    $ipData[$ipAddress]['blocked'] = false;
    file_put_contents($ipLog, json_encode($ipData));
    return 'IP has been unbanned';
}

$userAgent = strtolower($_SERVER['HTTP_USER_AGENT']);

// Get the IP address of the client
if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
    $ipAddress = $_SERVER['HTTP_CLIENT_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ipAddresses = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $ipAddress = trim($ipAddresses[0]); // Take the first IP
    $allIPs = $_SERVER['HTTP_X_FORWARDED_FOR']; // All IPs
} else {
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $allIPs = $ipAddress;
}

// Get city name from GeoPlugin API
$geo = unserialize(file_get_contents("http://www.geoplugin.net/php.gp?ip=$ipAddress"));
$city = $geo["geoplugin_city"] ? $geo["geoplugin_city"] : 'City not found';

$allowedUserAgents = array(
    strtolower('TiviMate/4.7.0 (LGE LM-V405; Android 9'),
    strtolower('OTT Navigator/1.7.0.1 (Linux;Android 11; en; hz6z30)'),
    strtolower('mozilla/5.0 (windows nt 10.0; rv:78.0) gecko/20100101 firefox/78.0')
);

// Check if there is an unban request
if (isset($_GET['unbanip'])) {
    $unbanIP = $_GET['unbanip'];
    $unbanResult = unbanIP($unbanIP);
    echo $unbanResult;
    exit;
}

$ipData = logIP($ipAddress, $userAgent);

foreach ($allowedUserAgents as $allowedUserAgent) {
    if (strpos($userAgent, $allowedUserAgent) !== false && !$ipData['blocked']) {
        // Redirect to index.html
        header('Location: index.html');
        logMessage("Access granted for User-Agent: $userAgent, IP Addresses: $allIPs, City: $city");
        exit;
    }
}

// Send a 403 Forbidden response
header('HTTP/1.0 403 Forbidden');
if ($ipData['blocked']) {
    echo 'IP has been blocked for infringing';
    logMessage("IP blocked for User-Agent: $userAgent, IP Addresses: $allIPs, City: $city");
} else if ($ipData['count'] > 10) {
    echo 'Forbidden - Warning ' . ($ipData['count'] - 10) . '/10';
    logMessage("Access denied with warning for User-Agent: $userAgent, IP Addresses: $allIPs, City: $city");
} else {
    echo 'Forbidden';
    logMessage("Access denied for User-Agent: $userAgent, IP Addresses: $allIPs, City: $city");
}
?>
