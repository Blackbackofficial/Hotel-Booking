# Booking Service

## Описание API
1. `POST /api/v1/booking` – создать резерв;
2. `POST /api/v1/booking` – все резервы пользователя (по куки);
2. `DELETE /api/v1/booking/canceled/{booking_uid}` – отменить бронь;
3. `POST /api/v1/booking/pay/{booking_uid}` – оплатить бронь;
4. `DELETE /api/v1/booking/reversed/{booking_uid}` – вернуть деньги по заказу.
5. `GET /api/v1/booking/{booking_uid}` - информация о брони
5. `GET /api/v1/booking/hotels/{hotel_uid}` - все брони отеля, доступно только админу

## Структура таблиц
```postgresql
CREATE TABLE Reservations
(
    booking_uid     UUID         NOT NULL,
    hotel_uid       SERIAL CONSTRAINT hotel_uid PRIMARY KEY
    user_uid        SERIAL CONSTRAINT user_uid PRIMARY KEY,
    payment_uid     SERIAL CONSTRAINT payment_uid PRIMARY KEY,
    date_start      TIMESTAMP [ without time zone ]
    date_end        TIMESTAMP [ without time zone ]
    comment         VARCHAR(255) NOT NULL,
);