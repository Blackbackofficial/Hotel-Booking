# Session Service

## Описание API
1. `POST /api/v1/session/register` – регистрация пользователя;
2. `POST /api/v1/session/login` – логирование пользователя, добавление в куки;
3. `GET /api/v1/session/verify` – проверка JWT авторизован или нет;
4. `GET /api/v1/session/refresh` – перевыпуск токена.
5. `GET /api/v1/session/users` – разлогинивание, удаление куки.
6. `POST /api/v1/session/logout` – разлогинивание, удаление куки.

## Структура таблиц
```postgresql
CREATE TABLE Users
(
    user_uid        SERIAL CONSTRAINT user_uid PRIMARY KEY,
    role            VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    email           VARCHAR(255) NOT NULL,
    password        VARCHAR(255) NOT NULL,
    username        VARCHAR(255) NOT NULL,
);