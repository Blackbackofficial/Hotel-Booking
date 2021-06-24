# pull official base image
FROM python:3.9
ENV PYTHONUNBUFFERED 1
RUN mkdir /usr/src/Booking_Service
COPY . /usr/src/Booking_Service
WORKDIR /usr/src/Booking_Service

RUN python3.9 -m pip install --upgrade pip
#ENV PYTHONPATH=/usr/local/lib/python3.9/site-packages/:/usr/src/Booking_Service
COPY ./requirements.txt .
RUN python3.9 -m pip install -r requirements.txt
ENTRYPOINT ["python3.9", "manage.py"]
CMD ["runserver", "0.0.0.0:8001"]