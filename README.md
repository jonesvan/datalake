# CLI
➜  php -S localhost:8080 api.php
➜  ./test.sh

# ToDos
- Client SDK
- complex Queries
- Example Projects
- Pub / Sub Websockets API
- siwtch do Golang and MongoDB or Redis?

# DataLake API Documentation

This documentation provides an overview of the DataLake API, a RESTful service for managing and querying objects with vector and geospatial data. The API supports user authentication, object CRUD operations, ownership management, event subscriptions, and advanced search capabilities.

## Table of Contents

- [Base URL](#base-url)
- [Authentication](#authentication)
- [Endpoints](#endpoints)
  - [User Registration](#user-registration)
  - [User Login](#user-login)
  - [Create Object](#create-object)
  - [Get Object](#get-object)
  - [Update Object](#update-object)
  - [Delete Object](#delete-object)
  - [List Objects](#list-objects)
  - [Add Owner to Object](#add-owner-to-object)
  - [Remove Owner from Object](#remove-owner-from-object)
  - [Search Objects by Vector Similarity](#search-objects-by-vector-similarity)
  - [Search Objects by Geolocation](#search-objects-by-geolocation)
  - [Subscribe to Events](#subscribe-to-events)
  - [Get Messages](#get-messages)
- [Data Models](#data-models)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Security Considerations](#security-considerations)

## Base URL

All API endpoints are relative to the base URL:

```
http://yourdomain.com/api/v1
```

## Authentication

The API uses token-based authentication. After logging in, clients receive a `session_token` which must be included in the `Authorization` header for all subsequent requests.

**Header Example:**

```
Authorization: Bearer your_session_token
```

## Endpoints

### User Registration

#### `POST /register`

Registers a new user.

**Request Body:**

```json
{
  "username": "johndoe",
  "password": "Password123"
}
```

**Response:**

- `200 OK` on success with a message.

```json
{
  "message": "User registered successfully"
}
```

### User Login

#### `POST /login`

Authenticates a user and returns a session token.

**Request Body:**

```json
{
  "username": "johndoe",
  "password": "Password123"
}
```

**Response:**

- `200 OK` on success with a session token.

```json
{
  "message": "Login successful",
  "session_token": "your_session_token"
}
```

### Create Object

#### `POST /objects`

Creates a new object.

**Headers:**

- `Authorization: Bearer your_session_token`

**Request Body:**

```json
{
  "type": "image",
  "timestamp": 1633017600,
  "data": {
    "url": "http://example.com/image.jpg",
    "description": "A sample image"
  },
  "location": {
    "latitude": 37.7749,
    "longitude": -122.4194
  }
}
```

**Response:**

- `200 OK` with the created object.

```json
{
  "uuid": "a1b2c3d4e5f6...",
  "type": "image",
  "timestamp": 1633017600,
  "data": { ... },
  "owners": ["johndoe"],
  "vector": [ ... ],
  "location": { ... }
}
```

### Get Object

#### `GET /objects/{uuid}`

Retrieves an object by its UUID.

**Headers:**

- `Authorization: Bearer your_session_token`

**Response:**

- `200 OK` with the object data.

```json
{
  "uuid": "a1b2c3d4e5f6...",
  "type": "image",
  "timestamp": 1633017600,
  "data": { ... },
  "owners": ["johndoe"],
  "vector": [ ... ],
  "location": { ... }
}
```

### Update Object

#### `PUT /objects/{uuid}`

Updates an existing object.

**Headers:**

- `Authorization: Bearer your_session_token`

**Request Body:**

- Fields to update (excluding `uuid` and `owners`).

```json
{
  "data": {
    "description": "An updated description"
  }
}
```

**Response:**

- `200 OK` with a success message.

```json
{
  "message": "Object updated successfully"
}
```

### Delete Object

#### `DELETE /objects/{uuid}`

Deletes an object.

**Headers:**

- `Authorization: Bearer your_session_token`

**Response:**

- `200 OK` with a success message.

```json
{
  "message": "Object deleted successfully"
}
```

### List Objects

#### `GET /objects`

Lists all objects owned by the authenticated user.

**Headers:**

- `Authorization: Bearer your_session_token`

**Query Parameters (Optional):**

- `type`: Filter objects by type.

**Response:**

- `200 OK` with a list of objects.

```json
[
  {
    "uuid": "a1b2c3d4e5f6...",
    "type": "image",
    "timestamp": 1633017600,
    "data": { ... },
    "owners": ["johndoe"],
    "vector": [ ... ],
    "location": { ... }
  },
  ...
]
```

### Add Owner to Object

#### `POST /objects/{uuid}/owners`

Adds a new owner to an object.

**Headers:**

- `Authorization: Bearer your_session_token`

**Request Body:**

```json
{
  "username": "janedoe"
}
```

**Response:**

- `200 OK` with a success message.

```json
{
  "message": "User 'janedoe' added as an owner"
}
```

### Remove Owner from Object

#### `DELETE /objects/{uuid}/owners/{username}`

Removes an owner from an object.

**Headers:**

- `Authorization: Bearer your_session_token`

**Response:**

- `200 OK` with a success message.

```json
{
  "message": "User 'janedoe' removed from owners"
}
```

### Search Objects by Vector Similarity

#### `POST /objects/search`

Searches objects based on vector similarity.

**Headers:**

- `Authorization: Bearer your_session_token`

**Request Body:**

```json
{
  "vector": [0.1, 0.2, 0.3, ...],  // Must be an array of numbers
  "top_k": 5  // Optional, defaults to 10
}
```

**Response:**

- `200 OK` with a list of objects and their similarity scores.

```json
[
  {
    "object": { ... },
    "similarity": 0.95
  },
  ...
]
```

### Search Objects by Geolocation

#### `POST /objects/geo_search`

Searches objects based on geographical proximity.

**Headers:**

- `Authorization: Bearer your_session_token`

**Request Body:**

```json
{
  "latitude": 37.7749,
  "longitude": -122.4194,
  "radius": 10  // Radius in kilometers
}
```

**Response:**

- `200 OK` with a list of objects and their distances.

```json
[
  {
    "object": { ... },
    "distance": 5.2  // Distance in kilometers
  },
  ...
]
```

### Subscribe to Events

#### `POST /subscribe`

Subscribes to a specific event type.

**Headers:**

- `Authorization: Bearer your_session_token`

**Request Body:**

```json
{
  "event_type": "object_created"
}
```

**Response:**

- `200 OK` with a success message.

```json
{
  "message": "Subscribed to event 'object_created'"
}
```

### Get Messages

#### `GET /messages`

Retrieves messages (events) for the authenticated user.

**Headers:**

- `Authorization: Bearer your_session_token`

**Response:**

- `200 OK` with a list of messages.

```json
[
  {
    "event_type": "object_created",
    "data": { ... },
    "timestamp": 1633017600
  },
  ...
]
```

## Data Models

### Object

- `uuid` (string): Unique identifier.
- `type` (string): Type of the object.
- `timestamp` (integer): Unix timestamp.
- `data` (object): Arbitrary data associated with the object.
- `owners` (array of strings): List of usernames who own the object.
- `vector` (array of floats): Generated vector for similarity search.
- `location` (object):
  - `latitude` (float): Latitude in degrees.
  - `longitude` (float): Longitude in degrees.
  - `altitude` (float, optional): Altitude in meters.

### User

- `username` (string): Unique username.
- `password_hash` (string): Hashed password.
- `objects` (array of strings): UUIDs of owned objects.

## Error Handling

The API uses standard HTTP status codes to indicate success or failure.

**Error Response Format:**

```json
{
  "error": "Error message describing what went wrong"
}
```

**Common Error Codes:**

- `400 Bad Request`: Invalid input or missing required fields.
- `401 Unauthorized`: Authentication failed or missing token.
- `403 Forbidden`: Access denied due to insufficient permissions.
- `404 Not Found`: Requested resource does not exist.
- `429 Too Many Requests`: Rate limit exceeded.
- `500 Internal Server Error`: An unexpected error occurred.

## Rate Limiting

- Clients are limited to **100 requests per minute**.
- Exceeding this limit results in a `429 Too Many Requests` error.

## Security Considerations

- **HTTPS Required**: All requests should be made over HTTPS to ensure data security.
- **Input Validation**: The API validates all input to prevent SQL injection, XSS, and other attacks.
- **Password Security**: Passwords are hashed using a strong algorithm.
- **Session Management**: Session tokens expire after 1 hour.
- **Rate Limiting**: Protects against DDoS attacks and abuse.
- **Headers for Security**: The API sets various HTTP headers to enhance security:
  - `Strict-Transport-Security`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Content-Security-Policy`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `X-XSS-Protection`

## Notes

- **Data Storage**: All data is stored in JSON files on the server.
- **Event Publishing**: Events are published to users who have subscribed to specific event types.
- **Ownership Management**: Users can share ownership of objects with others.
- **Search Functionality**: Advanced search capabilities using vector similarity and geolocation.

## Examples

### Register a New User

```bash
curl -X POST http://yourdomain.com/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
        "username": "johndoe",
        "password": "Password123"
      }'
```

### Log In

```bash
curl -X POST http://yourdomain.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{
        "username": "johndoe",
        "password": "Password123"
      }'
```

### Create an Object

```bash
curl -X POST http://yourdomain.com/api/v1/objects \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_session_token" \
  -d '{
        "type": "text",
        "timestamp": 1633017600,
        "data": {
          "content": "Hello, world!"
        },
        "location": {
          "latitude": 37.7749,
          "longitude": -122.4194
        }
      }'
```

## Conclusion

The DataLake API provides a robust set of features for managing objects with advanced search capabilities and event-driven interactions. Ensure that all requests comply with the security and input validation requirements to interact effectively with the API.

For any questions or issues, please contact the API support team.
