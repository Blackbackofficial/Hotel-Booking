# Hotels Service

## Описание API
1. `GET /api/v1/hotel/{hotel_uid}` – информация об отеле;
2. `DELETE /api/v1/hotel/{hotel_uid}` – удалить отель;
3. `GET /api/v1/hotel` – список отелей;
4. `POST /api/v1/hotel` – создать отель;
5. `DELETE /api/v1/hotel/{hotel_uid}/rooms` – изменить информацию о доступности комнат.

## Структура таблиц
```postgresql
CREATE TABLE Hotels
(
    hotel_uid       UUID         NOT NULL
    title           VARCHAR(255) NOT NULL,
    short_text      VARCHAR(255) NOT NULL,
    location        VARCHAR(255) NOT NULL,
    rooms           INTEGER      NOT NULL,
);