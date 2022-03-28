# Hotels Booking System

## Implementation Requirements

1. Implement a System consisting of several interacting services.
 Each service implements its own functionality and interacts with other services via the HTTP protocol (follow the RESTful notation) or through a queue.
 It is also allowed to use other protocols for inter-service communication, such as gRPC.
 
1. Each service has its own storage if it needs it.
 
1. Select a separate authorization service (Session Service), which stores information about users and
 used for user authorization and authentication.
 
1. For authorization, the user sends login + password, in response he receives a JWT token. The token is issued by the Session Service,
 token validation is also performed on the Session Service. Passwords are stored in the database in a hashed form.
 
1. Also highlight the Gateway Service, which will be the single point of entry into the system. All requests, except for user authorization,
 pass through it.
 
1. Validation of the custom JWT token is also performed by the Gateway service.
 
1. Because system components look at the Internet, implement cross-service authorization. Example:
    * if service A needs to make a request to service B, then it must receive a token for this;
    * service A has some clientId / clientSecret which it passes as basic authorization to service B and
      service B returns a signed JWT token in response;
    * system A retains this token and executes all subsequent requests with it;
    * the token has a lifetime, if its lifetime is over, then service B will return an HTTP 403:Forbidden error,
      it means that service A needs to re-obtain a token from system B and repeat the request with a new token;
    * only systems A and B participate in interservice authorization, Session Service is not involved.

1. Implement HTML+CSS user interface, preferably SPA (react, angular, vue) or mobile client.
 The use of CSS is required.
 
1. Requests from the UI can only be to the Gateway or Session Service to obtain a token.
 
1. Implement input data validation both on the front-end and on the back-end.
 
1. Implement the role model, create at least one user with the Admin role and one user with the User role.
 
1. Select a statistics service, send statistics on operations through the queue there. Depending on the task
 based on the received data, build a report, access to which should only be available to a user with the Admin role.
 
1. Provide for the situation of unavailability of systems, processing of timeouts and service errors. In case of error/unavailability
 non-critical functionality to degrade functionality.
 
1. Store all code on GitHub, automate the process of building, testing and releasing on an external platform.
 For CI/CD use Github Actions.
 
1. Assign a domain name to each service (possibly 3 or 4 levels), the main page should open
 by main name. For example:
    * UI: aero-ticket.ru
    * Gateway: gw.air-ticket.ru
    * Airport Service: airport.air-ticket.ru

## Common Methods

1. Authorization.
```
header: Authorization: basic(<login>:<password>)
POST /auth -> JWT token
```
1. Checking the user token.
```
header: Authorization: bearer <jwt>
POST /verify
```
1. List of all users. [A][G]
```
GET /users
```
1. Adding a new user. [A][G]
```
POST /users
body: { login, password }
```

Explanation:
* [S] – require authorization;
* [G] - the request goes through the Gateway Service.
* [A] – require authorization and administrator rights;
* [M] – modification operation.

The Data Structure block describes exemplary relationships between services and entities, this is not a description of an ER diagram or a database schema.

## Hotels Booking System

The system provides the user with a service for searching and booking hotels for the dates of interest. depending
Depending on the number of orders, the loyalty system gives the user a discount on new bookings.

**Business services:**

* Hotels (Hotel Service)
* Booking Service
* Payment system (Payment Service)
* Loyalty Service

**Additional services:**

*Gateway
* Authorization (Session Service)
* Admin (Report Service)

### Data structures

**User (Session Service):**
```
+ login
+ password
+ user_uid
```

**Hotels (Hotel Service):**
```
+ name
+ location: { country, city, address }
+ hotel_uid
```

**Reservations (Booking Service):**
```
+ hotel_uid -> FK to Hotel Service (Hotels::hotel_uid)
+ user_uid -> FK to Session Service (User::user_uid)
+ payment_uid-> FK to Payment Service (Payment::payment_uid)
+ booking_uid
+ date
+ comment
```

**Payments (Payment Service):**
```
+ payment_uid
+status [NEW, PAID, REVERSED, CANCELED]
+price
```

**UserLoyalty (Loyalty Service):**
```
+ user_uid -> FK to Session Service (User::user_uid)
+status: [BRONZE, SILVER, GOLD]
+ discount
```

### Basic operations

1. List of hotels. [G]
    ```
    GET /hotels
    ```
1. Information about the hotel. [G]
    ```
    GET /hotels/{hotelUid}
    ```
1. Book a room. [S][M][G]
    ```
    header: Authorization: bearer <jwt>
    POST /booking
    body: { hotelUid, room, paymentInfo }
    ```
1. Cancel your room reservation. [S][M][G]
    ```
    header: Authorization: bearer <jwt>
    DELETE /booking/{bookingUid}
    ```
1. Booking information. [S][G]
    ```
    header: Authorization: bearer <jwt>
    GET /booking/{bookingUid}
    ```
1. View my bookings. [S][G]
    ```
    header: Authorization: bearer <jwt>
    GET /booking
    ```
1. View the balance of the bonus program. [S][G]
    ```
    header: Authorization: bearer <jwt>
    GET /loyalty
    ```
1. Add a hotel. [A][M][G]
    ```
    header: Authorization: bearer <jwt>
    POST /hotels
    body: { rooms, name, address }
    ```
1. Change room availability information. [A][M][G]
    ```
    header: Authorization: bearer <jwt>
    PATCH /hotels/{hotelUid}/rooms
    body: { rooms: { number, interval, status } }
    ```
1. View booking statistics by users: when booking a hotel, data is sent to statistics. [A][G]
    ```
    header: Authorization: bearer <jwt>
    GET /reports/booking
    ```
1. View hotel occupancy statistics: how many places are free at the moment. [A][G]
    ```
    header: Authorization: bearer <jwt>
    GET /reports/hotels-filling
    ```
