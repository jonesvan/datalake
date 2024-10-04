#!/bin/bash

# test_api.sh
# A comprehensive script to test all API endpoints of api.php

API_URL="http://localhost:8080"

echo "Testing API endpoints..."

# Function to print a separator
print_separator() {
  echo "----------------------------------------"
}

# Function to pretty-print JSON responses
pretty_print() {
  if command -v jq &>/dev/null; then
    jq '.'
  else
    python -m json.tool 2>/dev/null
  fi
}

# Check if jq is installed
if ! command -v jq &>/dev/null; then
  echo "The 'jq' utility is required but not installed. Please install it and rerun the script."
  exit 1
fi

# Cleanup function to remove test data (optional)
cleanup() {
  echo "Cleaning up test data..."
  rm -rf data/
}

# Uncomment the following line to enable cleanup after tests
# trap cleanup EXIT

# Variables for test users
USERNAME1="testuser1"
USERNAME2="testuser2"
PASSWORD="Testpass1"

# 1. Register two new users
print_separator
echo "1. Registering two new users..."
USERS=("$USERNAME1" "$USERNAME2")
for USER in "${USERS[@]}"; do
  REGISTER_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$USER\", \"password\": \"$PASSWORD\"}")
  echo "Registering $USER:"
  echo "$REGISTER_RESPONSE" | pretty_print
done

# 2. Login with the first user
print_separator
echo "2. Logging in with the first user..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"$USERNAME1\", \"password\": \"$PASSWORD\"}")

echo "Response:"
echo "$LOGIN_RESPONSE" | pretty_print

# Extract the session token using jq
SESSION_TOKEN1=$(echo "$LOGIN_RESPONSE" | jq -r '.session_token')

if [ -z "$SESSION_TOKEN1" ] || [ "$SESSION_TOKEN1" == "null" ]; then
  echo "Failed to retrieve session token for $USERNAME1. Exiting."
  exit 1
fi

echo "Session Token for $USERNAME1: $SESSION_TOKEN1"

# Set the Authorization header for user 1
AUTH_HEADER1="Authorization: Bearer $SESSION_TOKEN1"

# 3. Login with the second user
print_separator
echo "3. Logging in with the second user..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"$USERNAME2\", \"password\": \"$PASSWORD\"}")

echo "Response:"
echo "$LOGIN_RESPONSE" | pretty_print

# Extract the session token using jq
SESSION_TOKEN2=$(echo "$LOGIN_RESPONSE" | jq -r '.session_token')

if [ -z "$SESSION_TOKEN2" ] || [ "$SESSION_TOKEN2" == "null" ]; then
  echo "Failed to retrieve session token for $USERNAME2. Exiting."
  exit 1
fi

echo "Session Token for $USERNAME2: $SESSION_TOKEN2"

# Set the Authorization header for user 2
AUTH_HEADER2="Authorization: Bearer $SESSION_TOKEN2"

# 4. User 1 subscribes to events
print_separator
echo "4. $USERNAME1 subscribes to events..."
EVENTS=("object_created" "object_updated" "object_deleted")
for EVENT in "${EVENTS[@]}"; do
  SUBSCRIBE_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/subscribe" \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER1" \
    -d "{\"event_type\": \"$EVENT\"}")
  echo "Subscribed to $EVENT:"
  echo "$SUBSCRIBE_RESPONSE" | pretty_print
done

# 5. User 1 creates multiple objects with location data
print_separator
echo "5. $USERNAME1 creates multiple objects with location data..."
OBJECT_UUIDS=()
LOCATIONS=(
  "37.7749,-122.4194,30.0"  # San Francisco
  "34.0522,-118.2437,50.0"  # Los Angeles
  "40.7128,-74.0060,10.0"   # New York
)
for LOCATION in "${LOCATIONS[@]}"; do
  IFS=',' read -r LATITUDE LONGITUDE ALTITUDE <<< "$LOCATION"
  OBJECT_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/objects" \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER1" \
    -d "{
      \"type\": \"note\",
      \"timestamp\": \"$(date +%s)\",
      \"data\": {
        \"title\": \"Note at $LATITUDE,$LONGITUDE\",
        \"content\": \"This is a test note located at $LATITUDE,$LONGITUDE.\"
      },
      \"location\": {
        \"latitude\": $LATITUDE,
        \"longitude\": $LONGITUDE,
        \"altitude\": $ALTITUDE
      }
    }")
  echo "Created object at $LATITUDE,$LONGITUDE:"
  echo "$OBJECT_RESPONSE" | pretty_print

  # Extract the object UUID
  OBJECT_UUID=$(echo "$OBJECT_RESPONSE" | jq -r '.uuid')
  if [ -n "$OBJECT_UUID" ] && [ "$OBJECT_UUID" != "null" ]; then
    OBJECT_UUIDS+=("$OBJECT_UUID")
  else
    echo "Failed to retrieve object UUID for object at $LATITUDE,$LONGITUDE."
  fi
done

# 6. Retrieve messages after object creation
print_separator
echo "6. $USERNAME1 retrieves messages after object creation..."
MESSAGES_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/messages" \
  -H "$AUTH_HEADER1")

echo "Messages:"
echo "$MESSAGES_RESPONSE" | pretty_print

# 7. User 1 updates the first object
print_separator
echo "7. $USERNAME1 updates the first object..."
FIRST_OBJECT_UUID=${OBJECT_UUIDS[0]}
UPDATE_RESPONSE=$(curl -s -X PUT "$API_URL/api/v1/objects/$FIRST_OBJECT_UUID" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER1" \
  -d "{
    \"data\": {
      \"title\": \"Updated Note\",
      \"content\": \"This note has been updated.\"
    },
    \"location\": {
      \"latitude\": 36.1699,
      \"longitude\": -115.1398,
      \"altitude\": 200.0
    }
  }")

echo "Response:"
echo "$UPDATE_RESPONSE" | pretty_print

# 8. Retrieve messages after object update
print_separator
echo "8. $USERNAME1 retrieves messages after object update..."
MESSAGES_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/messages" \
  -H "$AUTH_HEADER1")

echo "Messages:"
echo "$MESSAGES_RESPONSE" | pretty_print

# 9. User 1 performs a geospatial search
print_separator
echo "9. $USERNAME1 performs a geospatial search..."
SEARCH_LATITUDE=36.1699  # Las Vegas
SEARCH_LONGITUDE=-115.1398
RADIUS=500  # in kilometers

GEO_SEARCH_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/objects/geo_search" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER1" \
  -d "{
    \"latitude\": $SEARCH_LATITUDE,
    \"longitude\": $SEARCH_LONGITUDE,
    \"radius\": $RADIUS
  }")

echo "Geospatial Search Results:"
echo "$GEO_SEARCH_RESPONSE" | pretty_print

# 10. User 1 performs a vector similarity search
print_separator
echo "10. $USERNAME1 performs a vector similarity search..."
# Generate a vector similar to the first object's vector (for testing)
SIMILAR_VECTOR=$(echo '[0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5]')

VECTOR_SEARCH_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/objects/search" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER1" \
  -d "{
    \"vector\": $SIMILAR_VECTOR,
    \"top_k\": 5
  }")

echo "Vector Similarity Search Results:"
echo "$VECTOR_SEARCH_RESPONSE" | pretty_print

# 11. User 1 adds user 2 as an owner to the first object
print_separator
echo "11. $USERNAME1 adds $USERNAME2 as an owner to the first object..."
ADD_OWNER_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/objects/$FIRST_OBJECT_UUID/owners" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER1" \
  -d "{\"username\": \"$USERNAME2\"}")

echo "Response:"
echo "$ADD_OWNER_RESPONSE" | pretty_print

# 12. User 2 retrieves the object to verify ownership
print_separator
echo "12. $USERNAME2 retrieves the object to verify ownership..."
GET_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/objects/$FIRST_OBJECT_UUID" \
  -H "$AUTH_HEADER2")

echo "Response:"
echo "$GET_RESPONSE" | pretty_print

# 13. User 2 removes themselves as an owner
print_separator
echo "13. $USERNAME2 removes themselves as an owner..."
REMOVE_OWNER_RESPONSE=$(curl -s -X DELETE "$API_URL/api/v1/objects/$FIRST_OBJECT_UUID/owners/$USERNAME2" \
  -H "$AUTH_HEADER2")

echo "Response:"
echo "$REMOVE_OWNER_RESPONSE" | pretty_print

# 14. User 2 tries to retrieve the object again (should fail)
print_separator
echo "14. $USERNAME2 attempts to retrieve the object after removal..."
GET_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/objects/$FIRST_OBJECT_UUID" \
  -H "$AUTH_HEADER2")

echo "Response:"
echo "$GET_RESPONSE" | pretty_print

# 15. User 1 attempts to remove themselves as the last owner (should fail)
print_separator
echo "15. $USERNAME1 attempts to remove themselves as the last owner..."
REMOVE_OWNER_RESPONSE=$(curl -s -X DELETE "$API_URL/api/v1/objects/$FIRST_OBJECT_UUID/owners/$USERNAME1" \
  -H "$AUTH_HEADER1")

echo "Response:"
echo "$REMOVE_OWNER_RESPONSE" | pretty_print

# 16. User 1 deletes the object
print_separator
echo "16. $USERNAME1 deletes the first object..."
DELETE_RESPONSE=$(curl -s -X DELETE "$API_URL/api/v1/objects/$FIRST_OBJECT_UUID" \
  -H "$AUTH_HEADER1")

echo "Response:"
echo "$DELETE_RESPONSE" | pretty_print

# 17. User 1 retrieves messages after object deletion
print_separator
echo "17. $USERNAME1 retrieves messages after object deletion..."
MESSAGES_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/messages" \
  -H "$AUTH_HEADER1")

echo "Messages:"
echo "$MESSAGES_RESPONSE" | pretty_print

# 18. User 1 attempts to retrieve the deleted object (should fail)
print_separator
echo "18. $USERNAME1 attempts to retrieve the deleted object..."
GET_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/objects/$FIRST_OBJECT_UUID" \
  -H "$AUTH_HEADER1")

echo "Response:"
echo "$GET_RESPONSE" | pretty_print

# 19. Error handling: User 1 tries to create an object with invalid data
print_separator
echo "19. $USERNAME1 attempts to create an object with invalid data..."
INVALID_OBJECT_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/objects" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER1" \
  -d "{}")  # Missing required fields

echo "Response:"
echo "$INVALID_OBJECT_RESPONSE" | pretty_print

# 20. Error handling: User 1 attempts to login with incorrect password
print_separator
echo "20. $USERNAME1 attempts to login with incorrect password..."
INVALID_LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"$USERNAME1\", \"password\": \"WrongPass1\"}")

echo "Response:"
echo "$INVALID_LOGIN_RESPONSE" | pretty_print

# 21. Test rate limiting (optional and should be used with caution)
# Uncomment the following block to test rate limiting
: '
print_separator
echo "21. Testing rate limiting..."
for i in {1..110}; do
  RATE_LIMIT_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/objects" \
    -H "$AUTH_HEADER1")
  echo "Request $i Response Code: $(echo "$RATE_LIMIT_RESPONSE" | jq -r '.error // empty')"
done
'

echo "Testing completed."
