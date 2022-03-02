from sys import argv

from MHDDoS.start import start


def velyka_kara():
    if len(argv) < 5:
        print("Not enough arguments supplied. Please check the reference below:\n")

    start()


if __name__ == '__main__':
    velyka_kara()
