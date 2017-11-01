from getpass import getpass
from datetime import datetime
from math import trunc
from string import printable
from textwrap import wrap
from uuid import uuid4
from blessings import Terminal

import pickle
import os
import sys
import subprocess as sp


class Encoder:

    def __init__(self, debug=False):
        self._alphabet = {'0': 'b831', '1': 'fde8', '2': 'e51a', '3': '9dad', '4': 'ac42', '5': '837a', '6': '70c4', '7': '8d9a', '8': '2284', '9': '5d34', 'a': 'f990', 'b': '1103', 'c': 'fa40', 'd': 'fa2f', 'e': 'dfb8', 'f': '518f', 'g': 'a179', 'h': 'bc34', 'i': 'd97c', 'j': '8518', 'k': '16fb', 'l': '75a0', 'm': 'd923', 'n': 'bcc2', 'o': '5696', 'p': '8d43', 'q': '6d4a', 'r': '6285', 's': 'f93e', 't': 'ca6a', 'u': '8625', 'v': '9313', 'w': '54e2', 'x': 'c6ee', 'y': 'a373', 'z': 'e687', 'A': '1087', 'B': '7472', 'C': 'a8a0', 'D': '1620', 'E': '4004', 'F': '7171', 'G': 'f21c', 'H': 'ce6d', 'I': 'a8ae', 'J': '0b92', 'K': 'de3c', 'L': '2abc', 'M': 'ff18', 'N': 'fd97', 'O': 'f45d', 'P': '9ef6', 'Q': '52ec', 'R': '1fa0', 'S': 'a2ec', 'T': 'c711', 'U': '6b6d', 'V': 'f5f6', 'W': 'ef1e', 'X': '0878', 'Y': '026d', 'Z': '2119', '!': '946b', '"': '934a', '#': 'ad6f', '$': 'e9df', '%': '4f63', '&': '10f2', "'": 'e7a7', '(': 'b2d2', ')': 'c45f', '*': '63f5', '+': '4337', ',': '343e', '-': 'e1f7', '.': '3016', '/': 'faf6', ':': '34c6', ';': 'ae05', '<': '98cd', '=': '5fcf', '>': '723b', '?': '1ef6', '@': 'dd78', '[': '2599', '\\': 'fbb2', ']': '0c2c', '^': 'ecaf', '_': 'f1b9', '`': '3be1', '{': '0ef2', '|': '2b44', '}': '76fe', '~': 'cee5', ' ': 'ebe0'}
        self._messy = ''
        self._encoded = ''
        self._decoded = ''
        self._debug = debug

    def alphabet_generator(self):
        self._alphabet = {}

        for char in printable:
            self._alphabet[char] = uuid4().hex[0:4]

    def mess_up(self, text):
        upper = round(len(text) / 2) if not len(text) % 2 else trunc(len(text) / 2)
        downer = 0
        count = 0

        self._messy = ''
        for i in text:
            self._messy += text[downer] if count % 2 else text[upper]

            downer += 1 if count % 2 else 0
            upper += 0 if count % 2 else 1
            count += 1

    def encode(self, text):
        self.mess_up(text if type(text) is str else str(text))

        self._encoded = ''
        for char in self._messy:
            self._encoded += self._alphabet[char]

        return self._encoded

    def decode(self, text):
        deciphered = ''

        try:
            self._decoded = ''
            for part in wrap(text, 4):
                deciphered += list(self._alphabet.keys())[list(self._alphabet.values()).index(part)]

            count = 0
            for i in deciphered:
                self._decoded += i if count % 2 else ''
                count += 1

            count = 0
            for i in deciphered:
                self._decoded += i if not count % 2 else ''
                count += 1

        except Exception:
            if self._debug:
                print(t.bold_red('That text is not encoded by me or it was built with a different alphabet'))

        return self._decoded

    def json_encode(self, json):
        _json = {}

        for i in json:
            _json[i] = self.encode(json[i])

        return _json

    def json_decode(self, json):
        _json = {}

        for i in json:
            _json[i] = self.decode(json[i])

        return _json


class Backup:

    pool_path = '/var/backer-db/'

    defs = {
        'engines': {
            'mysql': {
                'port': '3306',
                'host': 'localhost'
            },
            'mongodb': {
                'port': '27017',
                'host': 'localhost'
            },
        },
        'args': {
            'pool': ['-p', '--pool'],
            'db': ['-db', '--databases'],
            'add': ['--create-pool', '-cp'],
            'ls': ['--list-pools', '-lp'],
            'rm': ['--remove-pool', '-rp'],
            'cl': ['--clean'],
            'days': ['--days', '-d']
        }
    }

    def __init__(self, pool=None, db_name=None):
        self.pool_name = pool
        self.db_name = db_name
        self.pool = {}
        self.args = {}

        os.system('mkdir -p ' + Backup.pool_path)

        self.args_builder()

    def make(self):
        if self._get_pool() is None or self.db_name is None:
            Backup.usage()

        pool = self._get_pool()
        dbs = self.db_name.split(' ')

        if bool(pool):
            for db in dbs:
                db_path = Backup.pool_path + pool['name'] + '/' + db + '/'
                os.system('mkdir -p ' + db_path)

                actions = {
                    'mysql': 'mysqldump -h {host} -u {user} --password="{psw}" -P {port} --routines --opt {db} > '
                             '{path}_`date +%d-%m-%Y`.sql &>/dev/null'.format(
                                host=pool['host'],
                                user=pool['user'],
                                psw=pool['psw'],
                                port=pool['port'],
                                db=db,
                                path=db_path + db
                             ),

                    'mongodb': 'mongodump --host {host} --port {port} --db {db} -u {user} -p {psw} '
                               '--authenticationDatabase "admin" --out {path}_`date +%d-%m-%Y` &>/dev/null'.format(
                                    host=pool['host'],
                                    user=pool['user'],
                                    psw=pool['psw'],
                                    port=pool['port'],
                                    db=db,
                                    path=db_path + db + '/' + db
                                )
                }

                os.system(actions.get(pool['engine']))

                print(t.bold_green('Succefully created: ' + db + '_' + sp.getoutput('date +%d-%m-%Y')))

    @staticmethod
    def list():
        os.system('mkdir -p ' + Backup.pool_path)

        if sp.getoutput(['ls ' + Backup.pool_path + ' | cut -f 1 -d "." | sort | wc -l']) == '0':
            print(t.bold_yellow('There is no pools yet...'))
        else:
            print(t.bold_green(sp.getoutput(['ls ' + Backup.pool_path + ' | grep .pkl | cut -f 1 -d "." | sort'])))

    @staticmethod
    def create_pool():
        os.system('mkdir -p ' + Backup.pool_path)

        try:
            pool = {}
            print(t.bold_cyan('Please add your new pool info: \n'))

            pool['name'] = Backup.validate(input(t.bold_yellow('Name: ')))

            print(t.bold_yellow('Which engine?: \n'))

            pools = list(Backup.defs['engines'])
            _pools = Backup.defs['engines']
            for item in range(len(pools)):
                print('   [' + t.bold_cyan(str(item)) + "]", pools[item])

            p = input(t.bold_yellow('\nMake your choice: '))

            pool['engine'] = pools[int(p)] if p != '' and int(p) < len(pools) else Backup.validate('')
            pool['user'] = Backup.validate(input(t.bold_yellow('Username: ')))
            pool['psw'] = getpass(t.bold_yellow('Password: '))
            pool['host'] = Backup.validate(input(t.bold_yellow('Hostname [' + _pools[pool['engine']].get('host') +
                                                               ']: ')), _pools[pool['engine']].get('host'))
            pool['port'] = Backup.validate(input(t.bold_yellow('Port [' + _pools[pool['engine']].get('port') +
                                                               ']:')), _pools[pool['engine']].get('port'))

            os.system('mkdir -p ' + Backup.pool_path + pool['name'])
            pickle.dump(Encoder().json_encode(pool), open(Backup.pool_path + pool['name'] + '.pkl', 'wb'))

            print(t.bold_green('\n Successfully created: ' + pool['name']))
        except Exception:
            pass

    def _get_pool(self):
        try:
            enc = Encoder()
            self.pool_name = str(self.pool_name)

            self.pool = pickle.load(open(Backup.pool_path + self.pool_name + '.pkl', 'rb'))
            self.pool = enc.json_decode(self.pool)

        except Exception:
            print(t.bold_red('There is no pool named: ' + self.pool_name + ', please add it'))
            exit(2)

        return self.pool

    def remove_pool(self):
        if self.pool_name is None:
            Backup.usage()

        if bool(self._get_pool()):
            os.system('rm ' + Backup.pool_path + self.pool_name + '.pkl')
            os.system('rm -r ' + Backup.pool_path + self.pool_name)

            print(t.bold_green('Succefully removed: ' + self.pool_name))

    @staticmethod
    def validate(_in, default=None):
        if len(_in) > 0:
            return _in
        elif default is not None:
            return default
        else:
            print(t.bold_red('This field is required'))
            exit(2)

    def cleaner(self, days=5):
        pool = self._get_pool()
        databases = self.db_name.split(' ')

        for db in databases:
            path = Backup.pool_path + self.pool_name + '/' + db + '/'
            backups = sp.getoutput('ls ' + path)
            backups = backups.split('\n')

            if len(backups) <= days:
                print(t.bold_green(db + ' is clean...\n'))
                continue

            ba = [datetime.strptime(x[-14:-4], '%d-%m-%Y') for x in backups]
            ba.sort()

            for x in ba[:-days]:
                if pool['engine'] == 'mysql':
                    os.remove(path + db + '_' + x.strftime('%d-%m-%Y') + '.sql')
                else:
                    os.removedirs(path + db + '_' + x.strftime('%d-%m-%Y'))

        print(t.bold_yellow('Databases cleaned...'))

    @staticmethod
    def usage():
        print("error: Invalid args \n")
        print("backer usage: backer [ -ARGS ] [ VALUE ] [ -OPTIONS] \n")
        print("              backer -p pool -db db \n")
        print("              backer -p pool -db \"db1 db2\" \n")
        print("              backer -p pool -db \"db1 db2\" --clean (for making and auto cleaning) \n")
        print("pools usage: backer [ -OPTIONS ] \n")
        print(" -ARGS:")
        print("  -p, --pool: Pool name")
        print("  -db, --databases: Database names as follows -> name or \"name1 name2\" ")
        print("\n -OPTIONS:")
        print("  -cp, --create-pool: Starts an interactive bash")
        print("  -lp, --list-pools: To get a list of pools")
        print("  -rp, --remove-pool: To remove a pool")
        print("  --clean: To clean a specified database or a list (-db \"name1 name2\")")
        print("  -d, --days: if --clean is passed will set the last days to keep at cleaning")
        exit()

    def _get_args(self):
        self.args = {}

        try:
            args = {}
            _args = sys.argv

            for i in range(len(_args)):
                if i % 2 and i < len(_args) - 1:
                    args[_args[i]] = _args[i + 1]
                elif i == len(_args) - 1 and not len(_args) % 2:
                    args[_args[i]] = 0

            requests = [ii for ii in args.keys()]
            for ii in requests:
                found = ([i for i in Backup.defs['args'] if ii in Backup.defs['args'][i]])

                if len(found) == 0:
                    continue

                self.args[found[0]] = args[ii]

            if not bool(self.args):
                Backup.usage()

        except Exception:
            pass

        return self.args

    def args_builder(self):
        requested = self._get_args()

        self.pool_name = requested['pool'] if 'pool' in requested else None
        self.db_name = requested['db'] if 'db' in requested else None

        if 'add' in requested:
            Backup.create_pool()

        if 'ls' in requested:
            Backup.list()

        if 'rm' in requested:
            self.pool_name = requested['rm'] if self.pool_name is None and 'rm' in requested else self.pool_name
            self.remove_pool()

        if 'db' in requested:
            if 'pool' in requested:
                self.make()
            else:
                Backup.usage()

        if 'cl' in requested:
            self.db_name = requested['cl'] if self.db_name is None and 'cl' in requested else self.db_name
            self.cleaner(int(requested['days']) if 'days' in requested else 5)


t = Terminal()

Backup()

