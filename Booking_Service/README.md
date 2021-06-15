# Booking Service

## Описание API
1. `POST /api/v1/booking` – создать резерв;
2. `POST /api/v1/booking` – все резервы пользователя (по куки);
3. `DELETE /api/v1/booking/canceled/{booking_uid}` – отменить бронь;
4. `POST /api/v1/booking/pay/{booking_uid}` – оплатить бронь;
5. `DELETE /api/v1/booking/reversed/{booking_uid}` – вернуть деньги по заказу.
6. `GET /api/v1/booking/{booking_uid}` - информация о брони
7. `GET /api/v1/booking/hotels/{hotel_uid}` - все брони отеля, доступно только админу
8. `GET /api/v1/booking/hotels/static` - все брони отелей, доступно только админу для отчета

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