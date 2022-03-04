# Швидкий старт ⚡

Оберіть свою платформу:

- [💻 Windows](#windows)
- [🐧 Linux](#linux)
- [🍎 Mac (Intel)](#mac-intel)
- [🍏 Mac (M1)](#mac-m1)
- [🐋 Docker](#docker)

---

### <a name="windows"></a>💻 Windows 

Щоб почати шкварити:

1. Активуйте VPN.
2. [Завантажте білд пиріжка.][pyrizhok-build-windows]
3. Запустіть _pyrizhok.exe_.
4. Введіть адресу цілі та натисніть Enter.

Коли настане час провітрити хату, натисніть _Ctrl+C_ або просто закрийте вікно з програмою.

---

### <a name="linux"></a>🐧 Linux

Щоб почати шкварити:

1. Активуйте VPN.
2. [Завантажте білд пиріжка.][pyrizhok-build-linux]
3. Запустіть _pyrizhok_.
4. Введіть адресу цілі та натисніть Enter.

Dlya fanativ terminalu:

2. Zavantazhte bild pyrizhka:
   ```bash
   curl TODO_LINK
   ```

3. Zapustit' pyrizhok adresoyu cili:
   ```bash
   ./pyrizhok https://voenny.korabl.net
   ```


Коли настане час провітрити хату, натисніть _Ctrl+C_ або просто закрийте вікно з програмою.

---

### <a name="mac-intel"></a>🍎 Mac (Intel)

Щоб почати шкварити:

1. Активуйте VPN.
2. [Завантажте білд пиріжка.][pyrizhok-build-mac-intel]
3. Запустіть pyrizhok.exe.
4. Введіть адресу цілі та натисніть Enter.

Коли настане час провітрити хату, натисніть _Ctrl+C_ або просто закрийте вікно з програмою.

---

### <a name="mac-m1"></a>🍏 Mac (M1)

Щоб почати шкварити:

1. Активуйте VPN.
2. [Завантажте білд пиріжка.][pyrizhok-build-mac-m1]
3. Запустіть pyrizhok.exe.
4. Введіть адресу цілі та натисніть Enter.

Коли настане час провітрити хату, натисніть _Ctrl+C_ або просто закрийте вікно з програмою.

---

### <a name="docker"></a>🐋 Docker

Щоб почати шкварити:

1. Активуйте VPN.
2. Запустіть пиріжок через Docker з адресою цілі:
    ```bash
    docker run -it pocketsunflower/pyrizhok:latest https://voenny.korabl.net
    ```
3. (опціонально) Якщо треба дамажити нестандартний порт та протокол, просто додайте їх до команди:
   ```bash
   docker run -it pocketsunflower/pyrizhok:latest https://voenny.korabl.net 53 TCP
   ```
   
Коли настане час провітрити хату, натисніть _Ctrl+C_ або вбийте контейнер іншим чином.

---

<div style="text-align: center">Все буде Україна 💙💛</div>


<!--- References --->
[mhddos-github]: https://github.com/MHProDev/MHDDoS
[pyrizhok-build-windows]: ../executables/Windows/pyrizhok.exe
[pyrizhok-build-linux]: ../executables/Linux/pyrizhok
[pyrizhok-build-mac-intel]: ../executables/Mac_Intel/pyrizhok.app
[pyrizhok-build-mac-m1]: ../executables/Mac_M1/pyrizhok.app
