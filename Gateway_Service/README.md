# Gateway Service

## Описание API
1. `POST /api/v1/login` – логирование (добавляется кука);
2. `POST /api/v1/register` – зарегистрироваться;
3. `GET /api/v1/logout` – выйти из учетной записи (удаляется кука);
4. `GET /api/v1/users` – все пользователи (только админ);
5. `GET /api/v1/hotels` – все отели;
6. `POST /api/v1/hotel` – добавить отель;
7. `GET /api/v1/hotels/{hotel_uid}` – информация об отеле;
8. `DELETE /api/v1/hotels/{hotel_uid}` – удалить определенный отель;
9. `POST /api/v1/booking` – создание брони;
10. `GET /api/v1/booking` – все брони пользователя;
11. `GET /api/v1/booking/{booking_uid}` – информация о броне;
12. `GET /api/v1/booking/hotels/{hotel_uid}` – все брони отеля (только админ);
13. `POST /api/v1/booking/{booking_uid}/pay` – оплатить бронь;
14. `POST /api/v1/booking/{booking_uid}/close` – отменить/вернуть деньги за бронь;
15. `GET /api/v1/reports/booking` – статистика бронирования по пользователям; (Kafka)
16. `GET /api/v1/reports/users` – статистика логирования, разлогирования пользователей; (Kafka)
17. `GET /api/v1/reports/hotels-filling` – статистика наполнения отелей

## Pages Hotel Booking

1. `GET /index` – страница отелей 
2. `GET/POST /register` – регистрация пользователя 
3. `GET /login` – вход пользователя
4. `GET /logout` – выход пользователя 
