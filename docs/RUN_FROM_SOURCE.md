# ⚡ Швидкий старт

Оберіть свою платформу:

- [💻 Windows](#windows)
- [🐧 Linux](#linux)
- [🍎 Mac (Intel)](#mac-intel) / [🍏 Mac (M1)](#mac-m1)
- [🐋 Docker](#docker)

> **ℹ** Якщо ви не довіряєте готовим білдам, скористайтеся [інструкцією для запуску паляниці з вихідного коду](RUN_FROM_SOURCE.md).

---

### <a name="windows"></a>💻 Windows 

Щоб почати шкварити:

1. Активуйте VPN.
2. Завантажте білд пиріжка [з GitHub.][pyrizhok-build-windows]
3. Запустіть **_pyrizhok.exe_** (подвійний клік). Якщо Windows поскаржиться, що програма з невідомого джерела - підтвердіть запуск, це нормально.
4. Введіть адресу цілі та натисніть Enter.
5. Опціонально можете обрати порт та метод атаки. Щоб використати базове значення, просто тисніть Enter.

Коли настане час провітрити хату, натисніть **_Ctrl+C_** або просто закрийте вікно з програмою.

---

### <a name="linux"></a>🐧 Linux

Щоб почати шкварити:

1. Активуйте VPN.
2. Завантажте білд пиріжка [з GitHub.][pyrizhok-build-linux]
3. Запустіть **_pyrizhok_** (подвійний клік).
4. Введіть адресу цілі та натисніть Enter.
5. Опціонально можете обрати порт та метод атаки. Щоб використати базове значення, просто тисніть Enter.

Якщо надаєте перевагу терміналу:

2. Завантажте білд пиріжка:
   ```bash
   wget https://github.com/pocket-sunflower/palyanytsya/raw/rozrobka/executables/Linux/pyrizhok
   ```
3. Запустіть пиріжок:
   ```bash
   ./pyrizhok
   ```

Коли настане час провітрити хату, натисніть **_Ctrl+C_** або просто закрийте вікно з програмою.

---

### <a name="mac-intel"></a>🍎 Mac (Intel)

Щоб почати шкварити:

1. Активуйте VPN.
2. Завантажте білд пиріжка [з GitHub][pyrizhok-build-mac-intel].
3. Запустіть **_pyrizhok_** (правою кнопкою миші по файлу, відкрити, погодитися на запуск). 
4. Введіть адресу цілі та натисніть Enter.
5. Опціонально можете обрати порт та метод атаки. Щоб використати базове значення, просто тисніть Enter.

Коли настане час провітрити хату, натисніть **_Ctrl+C_** або просто закрийте вікно з програмою.

---

### <a name="mac-m1"></a>🍏 Mac (M1)

Щоб почати шкварити:

1. Активуйте VPN.
2. Завантажте білд пиріжка [з GitHub][pyrizhok-build-mac-m1].
3. Запустіть **_pyrizhok_** (правою кнопкою миші по файлу, відкрити, погодитися на запуск). 
4. Введіть адресу цілі та натисніть Enter.
5. Опціонально можете обрати порт та метод атаки. Щоб використати базове значення, просто тисніть Enter.

Коли настане час провітрити хату, натисніть **_Ctrl+C_** або просто закрийте вікно з програмою.

---

### <a name="docker"></a>🐋 Docker

Щоб почати шкварити:

1. Активуйте VPN.
2. Запустіть пиріжок через Docker з адресою цілі:
    ```bash
    docker run -it pocketsunflower/pyrizhok:latest https://voenny.korabl.net
    ```
3. _(опціонально)_ Якщо треба дамажити нестандартний порт та змінити метод атаки, просто додайте їх до команди:
   ```bash
   docker run -it pocketsunflower/pyrizhok:latest https://voenny.korabl.net 53 TCP
   ```
   
Коли настане час провітрити хату, натисніть **_Ctrl+C_** або вбийте контейнер іншим чином.

---

<div style="text-align: center">Все буде Україна 💙💛</div>

[← Назад до головної](../README.md)


<!--- References --->
[mhddos-github]: https://github.com/MHProDev/MHDDoS
[pyrizhok-build-windows]: https://github.com/pocket-sunflower/palyanytsya/raw/rozrobka/executables/Windows/pyrizhok.exe
[pyrizhok-build-linux]: https://github.com/pocket-sunflower/palyanytsya/raw/rozrobka/executables/Linux/pyrizhok
[pyrizhok-build-mac-intel]: https://github.com/pocket-sunflower/palyanytsya/raw/rozrobka/executables/Mac%20(Intel)/pyrizhok
[pyrizhok-build-mac-m1]: https://github.com/pocket-sunflower/palyanytsya/blob/rozrobka/executables/Mac%20(M1)/pyrizhok
