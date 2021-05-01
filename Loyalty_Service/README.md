# Loyalty Service

## Описание API
1. `GET /api/v1/loyalty/balance` – баланс бонусной программы;
2. `POST /api/v1/loyalty/create` – создание баланса при регистрации;
3. `PATCH /api/v1/loyalty/edit-loyalty` – запрос повышения понижения лояльности;
4. `DELETE /api/v1/loyalty/delete` – удаление лояльности (при удалении пользователя).

## Структура таблиц
```postgresql
CREATE TABLE UserLoyalty
(
    user_uid        SERIAL CONSTRAINT user_uid PRIMARY KEY,
    discount        INTEGER      NOT NULL,
    status          VARCHAR(255) NOT NULL,
);