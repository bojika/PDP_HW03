## Задание: ## 
Реализовать деĸларативный языĸ описания и систему валидации запросов ĸ HTTP API сервиса сĸоринга. Шаблон уже есть в api.py, тесты в test.py, фунĸционал подсчета сĸора в scoring.py. API необычно тем, что пользователи дергают методы
POST запросами. Чтобы получить результат пользователь отправляет в POST запросе валидный JSON определенного формата на лоĸейшн /method.

### запуск скрипта ###

```
python api.py -h
Usage: api.py [options]

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT
  -l LOG, --log=LOG
```

### запуск тестов ###
```
python -m unittest test.py
```

но удобней это сделать через pytest

```
python -m pytest -vvv test.py
```
