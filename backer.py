from getpass import getpass
from datetime import datetime
from math import trunc
from string import printable
from textwrap import wrap
from uuid import uuid4
from blessings import Terminal
from shutil import rmtree

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
                print(t.red('That text is not encoded by me or it was built with a different alphabet'))

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

    _log_path = '/var/log/backer-error.log'

    _log_errors = ' 2>>{}'.format(_log_path)

    defs = {
        'engines': {
            'mysql': {
                'port': '3306',
                'host': 'localhost',
                'user': 'root',
                'backup': 'mysqldump -h {host} -u {user} --password="{psw}" -P {port} --routines --opt {db} > '
                          '{path}{db}_`date +%d-%m-%YT%H:%M:%S`.backup' + _log_errors,
                'restore': 'mysql -h {host} -u {user} --password="{psw}" -P {port} {db} < {backup}' + _log_errors,
                'get_db': 'echo "show databases;" | MYSQL_PWD={psw} mysql -h {host} -u {user} -P {port} |'
                          ' grep -Ev "Database|information_schema|performance_schema|sys|mysql"' + _log_errors
            },
            'postgresql': {
                'port': '5432',
                'host': 'localhost',
                'user': 'postgres',
                'backup': 'PGPASSWORD={psw} pg_dump -h {host} -U {user} -p {port} -F c {db} '
                          '> {path}{db}_`date +%d-%m-%YT%H:%M:%S`.backup' + _log_errors,
                'restore': 'PGPASSWORD={psw} pg_restore -h {host} -p {port} -U {user} -F c -d {db} --clean '
                           '{backup}' + _log_errors,
                'get_db': 'PGPASSWORD={psw} psql -h {host} -p {port} -U {user} -d postgres -t -A -c'
                          ' "SELECT datname FROM pg_database" | grep -Ev "template|postgres"' + _log_errors
            },
            'mongodb': {
                'port': '27017',
                'host': 'localhost',
                'backup': 'mongodump -h {host} --port {port} -d {db} -u {user} -p {psw} --gzip --authenticationDatabase'
                          ' "admin" --out {path}{db}_`date +%d-%m-%YT%H:%M:%S`.backup' + _log_errors,
                'restore': 'mongorestore -h {host} --port {port} -d {db} -u {user} -p {psw} --drop --gzip '
                           '--authenticationDatabase "admin" {backup}/{db}"' + _log_errors,
                'get_db': 'echo "show databases;" | mongo --host {host} --port {port} -u {user} -p {psw}'
                          ' --authenticationDatabase admin | grep GB | grep -Ev "admin|local|config"' + _log_errors
            },
        },
        'args': {
            'pool': ['-p', '--pool'],
            'db': ['-db', '--databases'],
            'add': ['--create-pool', '-cp'],
            'lp': ['--list-pools', '-lp'],
            'rm': ['--remove-pool', '-rp'],
            'cl': ['--clean'],
            'days': ['--days', '-d'],
            'ldb': ['--list-db'],
            'lb': ['--list-backups'],
            'res': ['--restore'],
            'all': ['--all']
        }
    }

    def __init__(self, pool=None, db_name=None):
        self.build_context()

        self.pool_name = pool
        self.db_name = db_name
        self.pool = {}
        self.args = {}
        self.args_builder()

    def build_context(self):
        if os.system('mkdir -p {} 2>/dev/null'.format(self.pool_path)) or \
           os.system('touch {} 2>/dev/null'.format(self._log_path)):
            print(t.red('Permission denied, please run this program as superuser'))
            exit(2)

    def get_databases(self):
        if self._get_pool() is None:
            self.usage()

        pool = self._get_pool()

        return sp.getoutput([self.defs['engines'][pool['engine']]['get_db'].format(**pool)]).split('\n')

    def make(self, _all=False):
        if self._get_pool() is None or (self.db_name is None and not _all):
            self.usage()

        pool = self._get_pool()
        dbs = self.get_databases() if _all else self.db_name.split(' ')

        if bool(pool):
            for db in dbs:
                db_path = self.pool_path + pool['name'] + '/' + db + '/'
                os.system('mkdir -p ' + db_path)

                status = os.system(self.defs['engines'][pool['engine']]['backup'].format(db=db, path=db_path, **pool))

                if not status:
                    print(t.green('Successfully created backup for database:'), t.italic_green(db))
                else:
                    print(t.red('Error trying to create backup for db: {}, check logs on {}'.format(db, self._log_path)))
                    target = '{}{}_{}.backup'.format(db_path, db, sp.getoutput('date +%d-%m-%YT%H:%M:%S'))
                    if os.path.isdir(target):
                        rmtree(target)

                    if os.path.isfile(target):
                        os.remove(target)

    @staticmethod
    def list_pool():
        if sp.getoutput(['ls ' + Backup.pool_path + ' | cut -f 1 -d "." | sort | wc -l']) == '0':
            print(t.italic_yellow('There is no pools yet...'))
        else:
            print(t.blue(sp.getoutput(['ls ' + Backup.pool_path + ' | grep .pkl | cut -f 1 -d "." | sort'])))

    def list_db(self):
        if sp.getoutput(['ls {}{} | wc -l'.format(self.pool_path, self.pool_name)]) == '0':
            print(t.italic_yellow('There is no databases in this pool yet...'))
        else:
            print(t.blue(sp.getoutput(['ls {}{} | sort'.format(self.pool_path, self.pool_name)])))

    def list_backs(self):
        if sp.getoutput(['ls {}{}{} | sort | wc -l'.format(self.pool_path, self.pool_name, self.db_name)]) == '0':
            print(t.italic_yellow('There is no backups yet...'))
        else:
            backups = sp.getoutput(['ls {}{}/{} | sort | nl'.format(self.pool_path, self.pool_name, self.db_name)])
            print(t.cyan('\n{}'.format(backups)))

            return [i.split('\t')[1] for i in backups.split('\n')]

    @staticmethod
    def create_pool():
        try:
            pool = {}
            print(t.cyan('Please add your new pool info: \n'))

            pool['name'] = Backup.validate(input(t.yellow('Name: ')))

            print(t.yellow('Which engine?: \n'))

            pools = list(Backup.defs['engines'])
            _pools = Backup.defs['engines']
            for item in range(len(pools)):
                print('   [' + t.cyan(str(item)) + "]", pools[item])

            p = input(t.italic_yellow('\nMake your choice: '))

            pool['engine'] = pools[int(p)] if p != '' and int(p) < len(pools) else Backup.validate('')
            pool['user'] = Backup.validate(input(t.yellow('Username: ')))
            pool['psw'] = getpass(t.yellow('Password: '))
            pool['host'] = Backup.validate(input(t.yellow('Hostname [' + _pools[pool['engine']].get('host') +
                                                               ']: ')), _pools[pool['engine']].get('host'))
            pool['port'] = Backup.validate(input(t.yellow('Port [' + _pools[pool['engine']].get('port') +
                                                               ']:')), _pools[pool['engine']].get('port'))

            os.system('mkdir -p ' + Backup.pool_path + pool['name'])
            pickle.dump(Encoder().json_encode(pool), open(Backup.pool_path + pool['name'] + '.pkl', 'wb'))

            print(t.green('\nSuccessfully created pool named: ' + pool['name']))
        except Exception:
            pass

    def _get_pool(self):
        try:
            enc = Encoder()
            self.pool_name = str(self.pool_name)

            self.pool = pickle.load(open(self.pool_path + self.pool_name + '.pkl', 'rb'))
            self.pool = enc.json_decode(self.pool)

        except Exception as e:
            print(t.red('There is no pool named: ' + self.pool_name + ', please add it'))
            exit(2)

        return self.pool

    def remove_pool(self):
        if self.pool_name is None:
            self.usage()

        if bool(self._get_pool()):
            os.system('rm ' + self.pool_path + self.pool_name + '.pkl')
            os.system('rm -r ' + self.pool_path + self.pool_name)

            print(t.green('Successfully removed: ' + self.pool_name))

    def restore(self):
        backs = self.list_backs()
        print(t.blue('     {}\tOther...'.format(len(backs) + 1)))

        choice = int(input(t.yellow('\nMake your choice [{}]: '.format(len(backs)))) or len(backs))

        if choice > len(backs):
            _choice = input(t.yellow('\nType backup full path: '))
        else:
            _choice = '{}{}/{}/{}'.format(self.pool_path, self.pool_name, self.db_name, backs[choice - 1])

        print(t.cyan('Restoring....'))

        bad = os.system(self.defs['engines'][self.pool['engine']]['restore'].format(db=self.db_name,
                                                                                    backup=_choice,
                                                                                    **self.pool))
        if not bad:
            print(t.green('\nSuccessfully restored: ' + _choice.split('/')[-1]))
        else:
            print(t.red('Something wrong trying to restore, check logs on {}'.format(self._log_path)))

    @staticmethod
    def validate(_in, default=None):
        if len(_in) > 0:
            return _in
        elif default is not None:
            return default
        else:
            print(t.red('This field is required'))
            exit(2)

    def cleaner(self, days=5):
        pool = self._get_pool()
        databases = self.db_name.split(' ')

        print()
        for db in databases:
            path = self.pool_path + self.pool_name + '/' + db + '/'
            backups = sp.getoutput('ls ' + path)
            backups = backups.split('\n')

            if len(backups) <= days:
                print(t.italic_yellow('The database ' + db + ' was already clean...'))
                continue

            ba = [datetime.strptime(x[-26:-7], '%d-%m-%YT%H:%M:%S') for x in backups]
            ba.sort()

            for x in ba[:-days]:
                target = '{}{}_{}.backup'.format(path, db, x.strftime('%d-%m-%YT%H:%M:%S'))
                if pool['engine'] != 'mongodb':
                    os.remove(target)
                else:
                    rmtree(target)

        print(t.blue('\nDatabases cleaned...'))

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
        print("  --list-db: List pool databases when used with --pool")
        print("  --list-backups: List database backups when used with -p and -db")
        print("  --clean: To clean a specified database or a list (-db \"name1 name2\")")
        print("  --restore: Interactive shell for restoring database when used with -p and -db")
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
                found = ([i for i in self.defs['args'] if ii in self.defs['args'][i]])

                if len(found) == 0:
                    continue

                self.args[found[0]] = args[ii]

            if not bool(self.args):
                self.usage()

        except Exception:
            pass

        return self.args

    def args_builder(self):
        requested = self._get_args()

        self.pool_name = requested['pool'] if 'pool' in requested else None
        self.db_name = requested['db'] if 'db' in requested else None

        if 'add' in requested:
            self.create_pool()

        if 'lp' in requested:
            self.list_pool()

        if 'rm' in requested:
            self.pool_name = requested['rm'] if self.pool_name is None and 'rm' in requested else self.pool_name
            self.remove_pool()

        if 'db' in requested or 'all' in requested:
            if 'pool' in requested:
                self.make('all' in requested)
            else:
                self.usage()

            if 'lb' in requested:
                self.list_backs()

            if 'res' in requested:
                self.restore()

        if 'pool' in requested and 'ldb' in requested:
            self.list_db()

        if 'cl' in requested:
            self.db_name = requested['cl'] if self.db_name is None and 'cl' in requested else self.db_name
            self.cleaner(int(requested['days']) if 'days' in requested else 5)


t = Terminal()

Backup()

