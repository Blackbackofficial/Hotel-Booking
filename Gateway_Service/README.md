# Gateway Service

## Описание API
1. `POST /api/v1/login` – логирование (добавляется кука);
2. `POST /api/v1/register` – зарегистрироваться;
3. `POST /api/v1/logout` – выйти из учетной записи (удаляется кука);
4. `GET /api/v1/users` – все пользователи (только админ);
5. `GET /api/v1/hotels` – все отели;
6. `POST /api/v1/hotel` – добавить отель;
7. `GET /api/v1/hotels/{hotel_uid}` – информация об отеле;
8. `DELETE /api/v1/hotels/{hotel_uid}` – удалить определенный отель;
9. `POST /api/v1/booking` – создание брони;
10. `GET /api/v1/booking` – все брони пользователя;
11. `GET /api/v1/booking/{booking_uid}` – информация о броне;
   
10. `GET /api/v1/hotel` – список отелей;
11. `POST /api/v1/hotel` – создать отель;
12. `DELETE /api/v1/hotel/{hotel_uid}/rooms` – изменить информацию о доступности комнат.

