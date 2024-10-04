<?php
// api.php

declare(strict_types=1);

namespace DataLake;

use Exception;

// Enforce HTTPS
/*
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    respondWithError(403, 'HTTPS is required');
}
    */

// Set headers for JSON response and security
header('Content-Type: application/json; charset=utf-8');
header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'); // HSTS
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox");
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: interest-cohort=()');
header('X-XSS-Protection: 1; mode=block');

// CORS policy
header('Access-Control-Allow-Origin: localhost');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Directory paths
define('DATA_DIR', __DIR__ . '/data');
define('OBJECTS_DIR', DATA_DIR . '/objects');
define('SUBSCRIPTIONS_DIR', DATA_DIR . '/subscriptions');
define('MESSAGES_DIR', DATA_DIR . '/messages');

// Ensure necessary directories exist with secure permissions
foreach ([DATA_DIR, OBJECTS_DIR, SUBSCRIPTIONS_DIR, MESSAGES_DIR] as $dir) {
    ensureDirectoryExists($dir);
}

/**
 * Ensure required directories exist with secure permissions.
 *
 * @param string $dir
 * @return void
 */
function ensureDirectoryExists(string $dir): void
{
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }
    chmod($dir, 0700);
}

/**
 * Read JSON data from a file with shared lock.
 *
 * @param string $filePath
 * @return array
 */
function readJsonFile(string $filePath): array
{
    if (!file_exists($filePath)) {
        return [];
    }

    $fp = fopen($filePath, 'r');
    if (flock($fp, LOCK_SH)) {
        $content = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        return json_decode($content, true) ?: [];
    }

    fclose($fp);
    respondWithError(500, 'Internal Server Error');
}

/**
 * Write JSON data to a file with exclusive lock.
 *
 * @param string $filePath
 * @param array  $data
 * @return void
 */
function writeJsonFile(string $filePath, array $data): void
{
    $tempFile = $filePath . '.tmp';
    $jsonData = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

    $fp = fopen($tempFile, 'w');
    if (flock($fp, LOCK_EX)) {
        fwrite($fp, $jsonData);
        fflush($fp);
        flock($fp, LOCK_UN);
    } else {
        fclose($fp);
        respondWithError(500, 'Internal Server Error');
    }
    fclose($fp);

    rename($tempFile, $filePath);
    chmod($filePath, 0600);
}

/**
 * Generate a UUID.
 *
 * @return string
 */
function generateUUID(): string
{
    return bin2hex(random_bytes(16));
}

/**
 * Authenticate user based on session token.
 *
 * @return string|null
 */
function authenticate(): ?string
{
    $headers = getRequestHeaders();
    $authHeader = $headers['Authorization'] ?? '';

    if (strpos($authHeader, 'Bearer ') === 0) {
        $sessionToken = substr($authHeader, 7);
    } else {
        return null;
    }

    $sessions = readJsonFile(DATA_DIR . '/sessions.json');
    $session = $sessions[$sessionToken] ?? null;

    if ($session && $session['expires'] > time()) {
        return $session['username'];
    }

    // Remove expired session
    if ($session) {
        unset($sessions[$sessionToken]);
        writeJsonFile(DATA_DIR . '/sessions.json', $sessions);
    }

    return null;
}

/**
 * Get request headers in a server-independent way.
 *
 * @return array
 */
function getRequestHeaders(): array
{
    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (str_starts_with($key, 'HTTP_')) {
            $header = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))));
            $headers[$header] = $value;
        }
    }
    return $headers;
}

/**
 * Register a new user.
 *
 * @param array $data
 * @return void
 */
function registerUser(array $data): void
{
    $username = trim($data['username'] ?? '');
    $password = $data['password'] ?? '';

    if (!$username || !$password) {
        respondWithError(400, 'Username and password are required');
    }

    if (!validateUsername($username) || !validatePassword($password)) {
        respondWithError(400, 'Invalid username or password format');
    }

    $users = readJsonFile(DATA_DIR . '/users.json');
    if (isset($users[$username])) {
        respondWithError(400, 'Username already exists');
    }

    $users[$username] = [
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'objects' => [],
    ];
    writeJsonFile(DATA_DIR . '/users.json', $users);

    respondWithMessage('User registered successfully');
}

/**
 * Log in a user and create a session token.
 *
 * @param array $data
 * @return void
 */
function loginUser(array $data): void
{
    $username = trim($data['username'] ?? '');
    $password = $data['password'] ?? '';

    if (!$username || !$password) {
        respondWithError(400, 'Username and password are required');
    }

    $users = readJsonFile(DATA_DIR . '/users.json');
    $user = $users[$username] ?? null;

    if (!$user || !password_verify($password, $user['password_hash'])) {
        respondWithError(401, 'Authentication failed');
    }

    $sessionToken = bin2hex(random_bytes(32));
    $sessions = readJsonFile(DATA_DIR . '/sessions.json');
    $sessions[$sessionToken] = [
        'username' => $username,
        'expires' => time() + 3600,
    ];
    writeJsonFile(DATA_DIR . '/sessions.json', $sessions);

    respondWithData([
        'message' => 'Login successful',
        'session_token' => $sessionToken,
    ]);
}

/**
 * Create a new object.
 *
 * @param array  $data
 * @param string $currentUser
 * @return void
 */
function createObject(array $data, string $currentUser): void
{
    $type = $data['type'] ?? null;
    $timestamp = $data['timestamp'] ?? null;
    $objectData = $data['data'] ?? null;
    $location = $data['location'] ?? null;

    if (!$type || !$timestamp || !$objectData || !$location) {
        respondWithError(400, 'Missing required fields');
    }

    if (!validateType($type) || !validateTimestamp($timestamp) || !validateLocation($location)) {
        respondWithError(400, 'Invalid input format');
    }

    $vector = generateVector($objectData);
    $uuid = generateUUID();
    $newObject = [
        'uuid' => $uuid,
        'type' => $type,
        'timestamp' => $timestamp,
        'data' => $objectData,
        'owners' => [$currentUser],
        'vector' => $vector,
        'location' => $location,
    ];

    writeJsonFile(OBJECTS_DIR . "/$uuid.json", $newObject);

    $users = readJsonFile(DATA_DIR . '/users.json');
    $users[$currentUser]['objects'][] = $uuid;
    writeJsonFile(DATA_DIR . '/users.json', $users);

    publishEvent('object_created', $newObject);

    respondWithData($newObject);
}

/**
 * Generate a vector based on object data.
 *
 * @param mixed $objectData
 * @return array
 */
function generateVector($objectData): array
{
    $hash = hash('sha256', json_encode($objectData));
    $vector = [];

    for ($i = 0; $i < 16; $i++) {
        $vector[] = hexdec(substr($hash, $i * 4, 4)) / 65535.0;
    }

    return $vector;
}

/**
 * Retrieve an object by UUID.
 *
 * @param string $uuid
 * @param string $currentUser
 * @return void
 */
function getObject(string $uuid, string $currentUser): void
{
    $object = getObjectById($uuid);

    if (!$object) {
        respondWithError(404, 'Object not found');
    }

    if (!authorizeUser($currentUser, $object['owners'])) {
        respondWithError(403, 'Access denied');
    }

    respondWithData($object);
}

/**
 * Update an existing object.
 *
 * @param string $uuid
 * @param array  $newData
 * @param string $currentUser
 * @return void
 */
function updateObject(string $uuid, array $newData, string $currentUser): void
{
    $object = getObjectById($uuid);

    if (!$object) {
        respondWithError(404, 'Object not found');
    }

    if (!authorizeUser($currentUser, $object['owners'])) {
        respondWithError(403, 'Access denied');
    }

    unset($newData['uuid'], $newData['owners']);

    if (isset($newData['location']) && !validateLocation($newData['location'])) {
        respondWithError(400, 'Invalid location format');
    }

    if (isset($newData['data'])) {
        $newData['vector'] = generateVector($newData['data']);
    }

    $updatedObject = array_merge($object, $newData);
    writeJsonFile(OBJECTS_DIR . "/$uuid.json", $updatedObject);

    publishEvent('object_updated', $updatedObject);

    respondWithMessage('Object updated successfully');
}

/**
 * Delete an object.
 *
 * @param string $uuid
 * @param string $currentUser
 * @return void
 */
function deleteObject(string $uuid, string $currentUser): void
{
    $object = getObjectById($uuid);

    if (!$object) {
        respondWithError(404, 'Object not found');
    }

    if (!authorizeUser($currentUser, $object['owners'])) {
        respondWithError(403, 'Access denied');
    }

    $object['owners'] = array_values(array_diff($object['owners'], [$currentUser]));

    if (empty($object['owners'])) {
        unlink(OBJECTS_DIR . "/$uuid.json");
    } else {
        writeJsonFile(OBJECTS_DIR . "/$uuid.json", $object);
    }

    $users = readJsonFile(DATA_DIR . '/users.json');
    $users[$currentUser]['objects'] = array_values(array_diff($users[$currentUser]['objects'], [$uuid]));
    writeJsonFile(DATA_DIR . '/users.json', $users);

    publishEvent('object_deleted', ['uuid' => $uuid]);

    respondWithMessage('Object deleted successfully');
}

/**
 * List objects for the current user, optionally filtered by type.
 *
 * @param string      $currentUser
 * @param string|null $type
 * @return void
 */
function listObjects(string $currentUser, ?string $type = null): void
{
    $users = readJsonFile(DATA_DIR . '/users.json');
    $userObjects = $users[$currentUser]['objects'] ?? [];

    $objects = [];
    foreach ($userObjects as $uuid) {
        $object = getObjectById($uuid);
        if ($object && ($type === null || $object['type'] === $type)) {
            $objects[] = $object;
        }
    }

    respondWithData($objects);
}

/**
 * Add a new owner to an object.
 *
 * @param string $uuid
 * @param array  $data
 * @param string $currentUser
 * @return void
 */
function addOwner(string $uuid, array $data, string $currentUser): void
{
    $newOwner = trim($data['username'] ?? '');

    if (!$newOwner) {
        respondWithError(400, 'Username is required to add as owner');
    }

    $users = readJsonFile(DATA_DIR . '/users.json');
    if (!isset($users[$newOwner])) {
        respondWithError(404, 'User not found');
    }

    $object = getObjectById($uuid);
    if (!$object) {
        respondWithError(404, 'Object not found');
    }

    if (!authorizeUser($currentUser, $object['owners'])) {
        respondWithError(403, 'Access denied');
    }

    if (in_array($newOwner, $object['owners'])) {
        respondWithError(400, 'User is already an owner');
    }

    $object['owners'][] = $newOwner;
    writeJsonFile(OBJECTS_DIR . "/$uuid.json", $object);

    $users[$newOwner]['objects'][] = $uuid;
    writeJsonFile(DATA_DIR . '/users.json', $users);

    respondWithMessage("User '$newOwner' added as an owner");
}

/**
 * Remove an owner from an object.
 *
 * @param string $uuid
 * @param string $username
 * @param string $currentUser
 * @return void
 */
function removeOwner(string $uuid, string $username, string $currentUser): void
{
    $users = readJsonFile(DATA_DIR . '/users.json');
    if (!isset($users[$username])) {
        respondWithError(404, 'User not found');
    }

    $object = getObjectById($uuid);
    if (!$object) {
        respondWithError(404, 'Object not found');
    }

    if (!authorizeUser($currentUser, $object['owners'])) {
        respondWithError(403, 'Access denied');
    }

    if (!in_array($username, $object['owners'])) {
        respondWithError(400, 'User is not an owner');
    }

    if (count($object['owners']) <= 1) {
        respondWithError(400, 'Cannot remove the last owner');
    }

    $object['owners'] = array_values(array_diff($object['owners'], [$username]));
    writeJsonFile(OBJECTS_DIR . "/$uuid.json", $object);

    $users[$username]['objects'] = array_values(array_diff($users[$username]['objects'], [$uuid]));
    writeJsonFile(DATA_DIR . '/users.json', $users);

    respondWithMessage("User '$username' removed from owners");
}

/**
 * Search objects based on vector similarity.
 *
 * @param array  $data
 * @param string $currentUser
 * @return void
 */
function searchObjects(array $data, string $currentUser): void
{
    $queryVector = $data['vector'] ?? null;
    $topK = max(1, intval($data['top_k'] ?? 10));

    if (!$queryVector || !is_array($queryVector) || !isValidVector($queryVector)) {
        respondWithError(400, 'Vector query is required and must be an array of numbers');
    }

    $users = readJsonFile(DATA_DIR . '/users.json');
    $userObjects = $users[$currentUser]['objects'] ?? [];

    $results = [];
    foreach ($userObjects as $uuid) {
        $object = getObjectById($uuid);
        if (isset($object['vector']) && is_array($object['vector'])) {
            $similarity = cosineSimilarity($queryVector, $object['vector']);
            $results[] = [
                'object' => $object,
                'similarity' => $similarity,
            ];
        }
    }

    usort($results, fn($a, $b) => $b['similarity'] <=> $a['similarity']);
    $topResults = array_slice($results, 0, $topK);

    respondWithData($topResults);
}

/**
 * Search objects based on geographical location.
 *
 * @param array  $data
 * @param string $currentUser
 * @return void
 */
function geoSearchObjects(array $data, string $currentUser): void
{
    $latitude = $data['latitude'] ?? null;
    $longitude = $data['longitude'] ?? null;
    $radius = $data['radius'] ?? null;

    if ($latitude === null || $longitude === null || $radius === null) {
        respondWithError(400, 'Latitude, longitude, and radius are required for geo search');
    }

    if (!validateLatitude($latitude) || !validateLongitude($longitude) || !is_numeric($radius) || $radius <= 0) {
        respondWithError(400, 'Invalid geo search parameters');
    }

    $users = readJsonFile(DATA_DIR . '/users.json');
    $userObjects = $users[$currentUser]['objects'] ?? [];

    $results = [];
    foreach ($userObjects as $uuid) {
        $object = getObjectById($uuid);
        if (isset($object['location'])) {
            $distance = haversineGreatCircleDistance(
                $latitude,
                $longitude,
                $object['location']['latitude'],
                $object['location']['longitude']
            );

            if ($distance <= $radius) {
                $results[] = [
                    'object' => $object,
                    'distance' => $distance,
                ];
            }
        }
    }

    usort($results, fn($a, $b) => $a['distance'] <=> $b['distance']);

    respondWithData($results);
}

/**
 * Calculate the Haversine distance between two points.
 *
 * @param float $latitudeFrom
 * @param float $longitudeFrom
 * @param float $latitudeTo
 * @param float $longitudeTo
 * @param int   $earthRadius
 * @return float
 */
function haversineGreatCircleDistance(
    float $latitudeFrom,
    float $longitudeFrom,
    float $latitudeTo,
    float $longitudeTo,
    int $earthRadius = 6371
): float {
    $latFrom = deg2rad($latitudeFrom);
    $lonFrom = deg2rad($longitudeFrom);
    $latTo = deg2rad($latitudeTo);
    $lonTo = deg2rad($longitudeTo);

    $latDelta = $latTo - $latFrom;
    $lonDelta = $lonTo - $lonFrom;

    $angle = 2 * asin(
        sqrt(
            pow(sin($latDelta / 2), 2) +
            cos($latFrom) * cos($latTo) * pow(sin($lonDelta / 2), 2)
        )
    );

    return $angle * $earthRadius;
}

/**
 * Calculate the cosine similarity between two vectors.
 *
 * @param array $vecA
 * @param array $vecB
 * @return float
 */
function cosineSimilarity(array $vecA, array $vecB): float
{
    $dotProduct = 0.0;
    $normA = 0.0;
    $normB = 0.0;
    $length = min(count($vecA), count($vecB));

    for ($i = 0; $i < $length; $i++) {
        $a = $vecA[$i];
        $b = $vecB[$i];
        $dotProduct += $a * $b;
        $normA += $a * $a;
        $normB += $b * $b;
    }

    if ($normA == 0 || $normB == 0) {
        return 0.0;
    }

    return $dotProduct / (sqrt($normA) * sqrt($normB));
}

/**
 * Subscribe to an event type.
 *
 * @param array  $data
 * @param string $currentUser
 * @return void
 */
function subscribe(array $data, string $currentUser): void
{
    $eventType = $data['event_type'] ?? null;

    if (!$eventType) {
        respondWithError(400, 'Event type is required');
    }

    $subscriptions = readJsonFile(SUBSCRIPTIONS_DIR . "/$currentUser.json");

    if (!in_array($eventType, $subscriptions)) {
        $subscriptions[] = $eventType;
        writeJsonFile(SUBSCRIPTIONS_DIR . "/$currentUser.json", $subscriptions);
    }

    respondWithMessage("Subscribed to event '$eventType'");
}

/**
 * Retrieve messages for the current user.
 *
 * @param string $currentUser
 * @return void
 */
function getMessages(string $currentUser): void
{
    $messages = readJsonFile(MESSAGES_DIR . "/$currentUser.json");
    writeJsonFile(MESSAGES_DIR . "/$currentUser.json", []);

    respondWithData($messages);
}

/**
 * Publish an event to subscribed users.
 *
 * @param string $eventType
 * @param array  $data
 * @return void
 */
function publishEvent(string $eventType, array $data): void
{
    $subscriptionFiles = glob(SUBSCRIPTIONS_DIR . '/*.json');

    foreach ($subscriptionFiles as $file) {
        $username = basename($file, '.json');
        $subscriptions = readJsonFile($file);

        if (in_array($eventType, $subscriptions)) {
            $userMessages = readJsonFile(MESSAGES_DIR . "/$username.json");
            $userMessages[] = [
                'event_type' => $eventType,
                'data' => $data,
                'timestamp' => time(),
            ];
            writeJsonFile(MESSAGES_DIR . "/$username.json", $userMessages);
        }
    }
}

/**
 * Retrieve an object by its UUID.
 *
 * @param string $uuid
 * @return array|null
 */
function getObjectById(string $uuid): ?array
{
    $filePath = OBJECTS_DIR . "/$uuid.json";

    if (!file_exists($filePath)) {
        return null;
    }

    return readJsonFile($filePath);
}

/**
 * Respond with a message.
 *
 * @param string $message
 * @param int    $statusCode
 * @return void
 */
function respondWithMessage(string $message, int $statusCode = 200): void
{
    http_response_code($statusCode);
    echo json_encode(['message' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Respond with an error message.
 *
 * @param int    $statusCode
 * @param string $message
 * @return void
 */
function respondWithError(int $statusCode, string $message): void
{
    http_response_code($statusCode);
    echo json_encode(['error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Respond with data.
 *
 * @param mixed $data
 * @param int   $statusCode
 * @return void
 */
function respondWithData($data, int $statusCode = 200): void
{
    http_response_code($statusCode);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Validate username format.
 *
 * @param string $username
 * @return bool
 */
function validateUsername(string $username): bool
{
    return preg_match('/^[a-zA-Z0-9]{3,20}$/', $username) === 1;
}

/**
 * Validate password format.
 *
 * @param string $password
 * @return bool
 */
function validatePassword(string $password): bool
{
    return preg_match('/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/', $password) === 1;
}

/**
 * Validate object type format.
 *
 * @param string $type
 * @return bool
 */
function validateType(string $type): bool
{
    return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $type) === 1;
}

/**
 * Validate timestamp.
 *
 * @param mixed $timestamp
 * @return bool
 */
function validateTimestamp($timestamp): bool
{
    return is_numeric($timestamp) && $timestamp >= 0 && $timestamp <= PHP_INT_MAX;
}

/**
 * Validate vector format.
 *
 * @param array $vector
 * @return bool
 */
function isValidVector(array $vector): bool
{
    foreach ($vector as $element) {
        if (!is_numeric($element)) {
            return false;
        }
    }
    return true;
}

/**
 * Validate location format.
 *
 * @param array $location
 * @return bool
 */
function validateLocation(array $location): bool
{
    return isset($location['latitude'], $location['longitude']) &&
        validateLatitude($location['latitude']) &&
        validateLongitude($location['longitude']) &&
        (!isset($location['altitude']) || is_numeric($location['altitude']));
}

/**
 * Validate latitude value.
 *
 * @param mixed $latitude
 * @return bool
 */
function validateLatitude($latitude): bool
{
    return is_numeric($latitude) && $latitude >= -90 && $latitude <= 90;
}

/**
 * Validate longitude value.
 *
 * @param mixed $longitude
 * @return bool
 */
function validateLongitude($longitude): bool
{
    return is_numeric($longitude) && $longitude >= -180 && $longitude <= 180;
}

/**
 * Check if user is authorized.
 *
 * @param string $currentUser
 * @param array  $owners
 * @return bool
 */
function authorizeUser(string $currentUser, array $owners): bool
{
    return in_array($currentUser, $owners);
}

/**
 * Clean up expired sessions.
 *
 * @return void
 */
function cleanUpExpiredSessions(): void
{
    $sessions = readJsonFile(DATA_DIR . '/sessions.json');
    $currentTime = time();

    $sessions = array_filter($sessions, fn($session) => $session['expires'] > $currentTime);
    writeJsonFile(DATA_DIR . '/sessions.json', $sessions);
}

/**
 * Clean up old rate limit data.
 *
 * @return void
 */
function cleanUpRateLimitData(): void
{
    $files = glob(DATA_DIR . '/rate_limit_*.json');
    $currentTime = time();

    foreach ($files as $file) {
        $data = readJsonFile($file);
        if (($currentTime - ($data['timestamp'] ?? 0)) > 3600) {
            unlink($file);
        }
    }
}

// Main Routing Logic
$method = $_SERVER['REQUEST_METHOD'];
$path = rtrim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');

// Clean up expired sessions periodically
if (rand(1, 100) === 1) {
    cleanUpExpiredSessions();
}

// Rate limiting
$ip = $_SERVER['REMOTE_ADDR'];
$rateLimitFile = DATA_DIR . "/rate_limit_$ip.json";
$rateLimitData = readJsonFile($rateLimitFile);

$currentTime = time();
$windowSize = 60; // seconds
$maxRequests = 100;

if (isset($rateLimitData['timestamp']) && ($currentTime - $rateLimitData['timestamp']) < $windowSize) {
    $rateLimitData['count']++;
    if ($rateLimitData['count'] > $maxRequests) {
        respondWithError(429, 'Too many requests. Please try again later.');
    }
} else {
    $rateLimitData = ['count' => 1, 'timestamp' => $currentTime];
}
writeJsonFile($rateLimitFile, $rateLimitData);

// Routing
try {
    switch ($method) {
        case 'POST':
            $data = json_decode(file_get_contents('php://input'), true);
            if ($path === '/api/v1/register') {
                registerUser($data);
            } elseif ($path === '/api/v1/login') {
                loginUser($data);
            } else {
                $currentUser = authenticate() ?? respondWithError(401, 'Unauthorized');
                if ($path === '/api/v1/objects') {
                    createObject($data, $currentUser);
                } elseif (preg_match('#^/api/v1/objects/([a-f0-9]{32})/owners$#', $path, $matches)) {
                    addOwner($matches[1], $data, $currentUser);
                } elseif ($path === '/api/v1/subscribe') {
                    subscribe($data, $currentUser);
                } elseif ($path === '/api/v1/objects/search') {
                    searchObjects($data, $currentUser);
                } elseif ($path === '/api/v1/objects/geo_search') {
                    geoSearchObjects($data, $currentUser);
                } else {
                    respondWithError(404, 'Endpoint not found');
                }
            }
            break;

        case 'GET':
            $currentUser = authenticate() ?? respondWithError(401, 'Unauthorized');
            if (preg_match('#^/api/v1/objects/([a-f0-9]{32})$#', $path, $matches)) {
                getObject($matches[1], $currentUser);
            } elseif ($path === '/api/v1/objects') {
                listObjects($currentUser, $_GET['type'] ?? null);
            } elseif ($path === '/api/v1/messages') {
                getMessages($currentUser);
            } else {
                respondWithError(404, 'Endpoint not found');
            }
            break;

        case 'PUT':
            $data = json_decode(file_get_contents('php://input'), true);
            $currentUser = authenticate() ?? respondWithError(401, 'Unauthorized');
            if (preg_match('#^/api/v1/objects/([a-f0-9]{32})$#', $path, $matches)) {
                updateObject($matches[1], $data, $currentUser);
            } else {
                respondWithError(404, 'Endpoint not found');
            }
            break;

        case 'DELETE':
            $currentUser = authenticate() ?? respondWithError(401, 'Unauthorized');
            if (preg_match('#^/api/v1/objects/([a-f0-9]{32})/owners/([a-zA-Z0-9]{3,20})$#', $path, $matches)) {
                removeOwner($matches[1], $matches[2], $currentUser);
            } elseif (preg_match('#^/api/v1/objects/([a-f0-9]{32})$#', $path, $matches)) {
                deleteObject($matches[1], $currentUser);
            } else {
                respondWithError(404, 'Endpoint not found');
            }
            break;

        default:
            respondWithError(405, 'Method Not Allowed');
    }
} catch (Exception $e) {
    respondWithError(500, 'Internal Server Error');
}

// Clean up rate limit data periodically
if (rand(1, 100) === 1) {
    cleanUpRateLimitData();
}
