# Loyalty Service

## Описание API
1. `POST /api/v1/payment/create` – создать оплату;
2. `POST /api/v1/payment/pay/{payment_uid}` – оплатить бронь;
3. `POST /api/v1/payment/reversed/{payment_uid}` – вернуть деньги (если пользователь оплатил и отменяет);
4. `DELETE /api/v1/payment/close/{payment_uid}` – закрыть бронь (если пользователь НЕ оплатил и отменяет).
5. `GET /api/v1/payment/close/status/{payment_uid}` - статус брони

## Структура таблиц
```postgresql
CREATE TABLE Payment
(
    payment_uid     UUID         NOT NULL,
    status          VARCHAR(255) NOT NULL,
    price           INTEGER      NOT NULL,
);