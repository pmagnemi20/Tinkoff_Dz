# Homework 1 [Lecture 3] - Infrastructure security

## Эксплуатация уязвимости Zerologon

Для этого я развернул в сети с предыдущей домашки две вмки:
1) Windows Server 2016, настроил дебаг для netlogon + активировал DC + настроил политики на домен контроллере
ip: 192.168.1.19
Лес: TESTDOMAIN.local
Названия сервера: WIN-VICTIM

![](https://i.imgur.com/TeXjr8E.png)


2) Kali Linux

Воспользуюсь я експлойтом от VoidSec. Установив все зависимости, пробую атаковать сервер

![](https://i.imgur.com/FG4eUgJ.png)

Сервер уязвим.

Начинаем атаку.

![](https://i.imgur.com/WKWt650.png)


Атака прошла успешно, можно попробовать сдампить хэши от пользаков. Тем самым мы получаем хэш пароля от Админа. Можно попробовать зайти удаленно через SMB.


![](https://i.imgur.com/CT4QuWB.png)


Я удаленно подключился к DC и могу добавлять новых пользователей, группы, менять что угодно.

Скрин netlogon.txt, также выгружу его.

![](https://i.imgur.com/CLZ28Uu.png)


Скрин с вайршарка, в конце все таки удалось найти такой сессион кей, когда первый блок оказался 00.

![](https://i.imgur.com/76QRoPr.png)

Коды событий:

4672 - вход привилегированной УЗ

![](https://i.imgur.com/QuDcovx.png)

4742 - изменение объекта компьютера

![](https://i.imgur.com/OI9hrLe.png)

Таким образом, я сбросил пароль и получил полный контроль над доменом. Чтобы не сломать сервер, нужно вернуть исходный пароль. Получил хэш исходного пароля, я поставил его обратно, тем самым не сломав тачку. 


![](https://i.imgur.com/vp5CPkE.png)


Пароль успешно восстановлен.

## Эксплуатация уязвимости noPAC

Здесь буду использовать другой образ Винды, че то с предыдущим не пошло:


![](https://i.imgur.com/z0nyzd3.png)


Создаем пользака с минимальными правами:

![](https://i.imgur.com/uH3MF4v.png)


Начинаем атаку:

![](https://i.imgur.com/Pj1K1HB.png)


Netlogon увидел что машина kalI подключилась удаленно.
По событиям:
После того как я набрал hostname

![](https://i.imgur.com/KwfZApm.png)

В событиях отобразились ивенты с Керберосом+проверка учетных данных


![](https://i.imgur.com/FlNqiKa.png)


Таким образом,я получил RCE.

