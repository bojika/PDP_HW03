#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
import scoring
import re

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(object):
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return instance.__dict__.get(self.name, None)

    def __set__(self, instance, value):
        instance.__dict__[self.name] = value


class CharField(Field):
    def __set__(self, instance, value):
        if not isinstance(value, str):
            raise TypeError(f'{self.name} must be a str')
        instance.__dict__[self.name] = value


class ArgumentsField(CharField):
    def __set__(self, instance, value):
        if not isinstance(value, dict):
            raise TypeError(f'{self.name} must be a dict')
        instance.__dict__[self.name] = value


class EmailField(CharField):
    def __set__(self, instance, value):
        super().__set__(instance, value)
        if not re.match(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', value):
            raise TypeError(f'{self.name} must be valid email address')


class PhoneField(Field):
    def __set__(self, instance, value):
        if not re.match(r'^7[0-9]{10}$', str(value)):
            raise TypeError(f'{self.name} must contain 11 digits starting with 7')
        instance.__dict__[self.name] = str(value) if value is not None else value


class DateField(CharField):
    def __set__(self, instance, value):
        super().__set__(instance, value)
        try:
            datetime.datetime.strptime(value, '%d.%m.%Y')
        except (ValueError, TypeError):
            raise TypeError(f'{self.name} must be in the following format: DD.MM.YYYY')


class BirthDayField(DateField):
    MAX_AGE = 70

    def __set__(self, instance, value):
        super().__set__(instance, value)
        birthday = datetime.datetime.strptime(value, '%d.%m.%Y')
        # нельзя сравнить timedelta и MAX_AGE, так как не учитывается високосность года
        # поэтому будем проверять, что наша дата лежит между
        # текущей датой и этой же датой MAX_AGE лет назад
        now = datetime.datetime.now()
        # type(self) или self.__class__? лучше type(self)
        max_age_ago = f'{now.day}.{now.month}.{now.year - type(self).MAX_AGE}'
        max_age_ago = datetime.datetime.strptime(max_age_ago, '%d.%m.%Y')
        if not (max_age_ago <= birthday <= now):
            raise TypeError(f"Birthday must be in a range [{max_age_ago.strftime('%d.%m.%Y')}, {now.strftime('%d.%m.%Y')}]")


class NumericField(Field):
    def __set__(self, instance, value):
        if not isinstance(value, int):
            raise TypeError(f'{self.name} must be a int')
        instance.__dict__[self.name] = value


class GenderField(Field):
    def __set__(self, instance, value):
        super().__set__(instance, value)
        if value not in GENDERS.keys():
            raise TypeError('gender must be 0, 1 or 2')


class ClientIDsField(Field):
    def __set__(self, instance, value):
        if not isinstance(value, list):
            raise TypeError(f'{self.name} must be a list')
        if not all([isinstance(item, int) for item in value]):
            raise TypeError(f'{self.name} must be a list of int')
        instance.__dict__[self.name] = value


class Request:
    def __init__(self, **kwargs):
        # print(vars(self.__class__))
        for key, v in vars(type(self)).items():
            if isinstance(v, Field):
                # print(f'{key=} {getattr(v, "required")=}')
                # required - это field in message
                if getattr(v, "required") and key not in kwargs.keys():
                    raise TypeError(f"Tребуемое поле {key} отсутствует")
                # нет смысла проверять корректность данных, надо обойти setter
                if not getattr(v, "required") and getattr(v, "nullable") and kwargs.get(key, None) is None:
                    v.__dict__[key] = None
                    continue
                # nullable - это message[field] = None
                # оказывается, что nullable - это не только message[field] = None
                # но и в случае списка - пустой список
                if not getattr(v, "nullable") and kwargs.get(key, None) in [None, []]:
                    raise TypeError(f"Поле {key} должно быть определено")
                # остальные проверки корректности данных реализуем через setter
                setattr(self, key, kwargs.get(key, None))


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not any([self.phone and self.email,
                    self.first_name and self.last_name,
                    self.gender in GENDERS.keys() and self.birthday]):
            raise TypeError('(phone, email) or (first_name, last_name) or (gender, birthday) must be not empty')


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        msg = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
        digest = hashlib.sha512(msg.encode('UTF-8')).hexdigest()
    else:
        msg = request.account + request.login + SALT
        digest = hashlib.sha512(msg.encode('UTF-8')).hexdigest()
    if digest == request.token:
        return True
    return False


def clients_interest_handler(request, ctx, store):
    model = ClientsInterestsRequest(**request.arguments)
    # model.validate()

    ctx['nclients'] = len(model.client_ids)

    response = {x: scoring.get_interests(store, x) for x in model.client_ids}
    return response, OK


def online_score_handler(request, ctx, store):
    model = OnlineScoreRequest(**request.arguments)
    # model.validate()

    # в словарь контекста должна прописываться запись "has" - список полей,
    # которые были не пустые для данного запроса
    ctx['has'] = [name for name in vars(model) if getattr(model, name) is not None]

    # если пользователь админ, то нужно всегда отдавать 42
    if request.is_admin:
        response, code = dict(score=42), OK
    else:
        score = scoring.get_score(store=store,
                                  phone=model.phone,
                                  email=model.email,
                                  birthday=model.birthday,
                                  gender=model.gender,
                                  first_name=model.first_name,
                                  last_name=model.last_name)
        response, code = dict(score=score), OK
    return response, code


def get_handler(method):
    # возвращает функцию обработчик или None, если неизвестный метод
    handlers = {
        'online_score': online_score_handler,
        'clients_interests': clients_interest_handler
    }
    return handlers.get(method, None)


def method_handler(request, ctx, store):
    body = request.get('body')
    if not isinstance(body, dict):
        return 'No data in the request', INVALID_REQUEST
    # дальше будем валидировать запрос
    try:
        method_request = MethodRequest(**body)
        # method_request.validate()
    except TypeError as e:
        logging.exception(e)
        return str(e), INVALID_REQUEST
    # для начала, проверим аутентификацию
    if not check_auth(method_request):
        return None, FORBIDDEN
    # итого, запрос валиден
    # получим обработчик метода из запроса
    handler = get_handler(method_request.method)
    if not handler:
        return f'Unknown method {method_request.method}', INVALID_REQUEST
    # и вызовем его
    try:
        return handler(request=method_request, ctx=ctx, store=store)
    except TypeError as e:
        logging.exception(e)
        return str(e), INVALID_REQUEST


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        # получим после post в request подобный словарь
        # {'account': 'horns&hoofs', 'login': 'admin', 'method': 'clients_interests',
        #  'token': 'd9c2ea142fafbf290b35fcf7bdf5209c700acbb59f731f2f41256fbdf923079680ade77756b8f3fda7d6c8e327af5a7d126121727b99ae1ca4f4c58747bd3629',
        #  'arguments': {'client_ids': [1, 2, 3, 4], 'date': '20.07.2017'}}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            # сюда получим url по которому был запрос
            # если было http://localhost:8080/method - получу '/method'
            path = self.path.strip("/")
            # context["request_id"] - идентификатор запроса
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    # по path получим функцию обработчик и передадим в неё построенные аргументы
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
