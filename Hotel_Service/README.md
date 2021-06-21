# Hotels Service

## Описание API
1. `GET /api/v1/hotels/{hotel_uid}` – информация об отеле;
2. `DELETE /api/v1/hotels/{hotel_uid}` – удалить отель;
3. `GET /api/v1/hotels` – список отелей;
4. `GET /api/v1/hotels/cities` – список доступных городов отелей;
5. `POST /api/v1/hotels` – создать отель;
6. `DELETE /api/v1/hotels/{hotel_uid}/rooms` – изменить информацию о доступности комнат.

## Структура таблиц
```postgresql
CREATE TABLE Hotels
(
    hotel_uid       UUID         NOT NULL
    title           VARCHAR(255) NOT NULL,
    short_text      VARCHAR(255) NOT NULL,
    cities          VARCHAR(255) NOT NULL,
    location        VARCHAR(255) NOT NULL,
    rooms           INTEGER      NOT NULL,
); 