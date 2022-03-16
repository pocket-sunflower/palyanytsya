# 🍞 Випічка

У цьому документі зібрані інструкції щодо того, як можна запакувати пиріжок та паляницю у самостійні виконувані файли. 

Якщо ви вирішили братися за це діло, ми припускаємо, що ви володієте певним рівнем обізнаності в роботі з терміналом та Python проектами. Через це ми приводимо детальні інструкції з випічки тільки для Linux та Docker платформ. Випічка на Mac та Windows за своєю суттю ідентична до процесу в Linux.

---

## Linux та інші платформи

1. Завантажте проект через git:
    ```bash
    git clone https://github.com/pocket-sunflower/palyanytsya
    ```

2. Перейдіть до папки проекту:
    ```bash
    cd palyanytsya 
    ```

3. Створіть нове віртуальне середовище:
    > **⚠** Паляниця з пиріжком потребують версію Python не менше ніж [**3.10.2**](https://www.python.org/downloads/release/python-3102/).
    ```bash
    python3 -m virtualenv --python python3.10 venv
    ```

4. Встановіть залежності:
   ```bash
   pip install -r requirements.txt
   ```

6. Активуйте віртуальне середовище:
    ```bash
    source venv/bin/activate
    ```

7. Перейдіть до папки з Python-скриптами для створення виконуваних файлів:
    ```bash
    cd build_scripts_PyInstaller
    ```

8. Запустіть створення білда:
    ```bash
    python build_for_linux.py
    ```

9. Дочекайтеся завершення білда. В результаті ви отримаєте два виконувані файли в папці **_executables/Linux_**: **_pyrizhok_** та **_palyanytsya_**.

Процес створення білдів для Mac та Windows – ідентичний. Викорустуйте команди для створення та активації віртуального середовища на вашій відповідній платформі, а потім запустіть відповідний білд-скрипт (наприклад, для Маків з процесором M1 це буде **_build_for_mac_m1.py_**). Запаковані файли будут знаходитися у відповідній папці під executables.

---

## Docker

1. Завантажте проект через git:
    ```bash
    git clone https://github.com/pocket-sunflower/palyanytsya
    ```

2. Перейдіть до папки з bash-скриптами для створення Docker білдів:
    ```bash
    cd palyanytsya/build_scripts_Docker
    ```

3. Запустіть білд:
    ```bash
    bash build_dockers.sh
    ```

Дочекайтеся завершення білда. В результаті у вашому Docker з‘являться нові контейнери: **_pyrizhok:latest_** та **_palyanytsya:latest_**. Випічка завершена!

---

<div style="text-align: center">Все буде Україна 💙💛</div>

[← Назад до головної](../README.md)