from getpass import getpass
from datetime import datetime
from math import trunc
from string import printable
from textwrap import wrap
from uuid import uuid4
from blessings import Terminal
from shutil import rmtree
from subprocess import getoutput as go
from argparse import ArgumentParser
from pickle import dump, load
from os import system, path, remove


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
                'get_db': 'echo "show databases;" | MYSQL_PWD="{psw}" mysql -h {host} -u {user} -P {port} |'
                          ' grep -Ev "Database|information_schema|performance_schema|sys|mysql"' + _log_errors
            },
            'postgresql': {
                'port': '5432',
                'host': 'localhost',
                'user': 'postgres',
                'backup': 'PGPASSWORD="{psw}" pg_dump -h {host} -U {user} -p {port} -F c {db} '
                          '> {path}{db}_`date +%d-%m-%YT%H:%M:%S`.backup' + _log_errors,
                'restore': 'PGPASSWORD="{psw}" pg_restore -h {host} -p {port} -U {user} -F c -d {db} --clean '
                           '{backup}' + _log_errors,
                'get_db': 'PGPASSWORD="{psw}" psql -h {host} -p {port} -U {user} -d postgres -t -A -c'
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
    }

    def __init__(self, pool=None, db_name=None):
        self.build_context()

        if pool:
            self._set_pool(pool)
        self.db = db_name
        self.pool = {}
        self._args_builder()

    def build_context(self):
        if system('mkdir -p {} 2>/dev/null'.format(self.pool_path)) or \
           system('touch {} 2>/dev/null'.format(self._log_path)):
            print(t.red('Permission denied, please run this program as superuser'))
            exit(2)

    def _set_databases(self, db):
        self.db = db if type(db) == list else [i.split(' ')[0] for i in go([self.defs['engines'][self.pool['engine']]['get_db'].format(**self.pool)]).split('\n')]

    def make(self):
        for db in self.db:
            db_path = self.pool_path + self.pool['name'] + '/' + db + '/'
            system('mkdir -p ' + db_path)

            status = system(self.defs['engines'][self.pool['engine']]['backup'].format(db=db, path=db_path, **self.pool))

            if not status:
                print(t.green('Successfully created backup for database:'), t.italic_green(db))
            else:
                print(t.red('Error trying to create backup for db: {}, check logs on {}'.format(db, self._log_path)))
                target = '{}{}_{}.backup'.format(db_path, db, go('date +%d-%m-%YT%H:%M:%S'))
                if path.isdir(target):
                    rmtree(target)

                if path.isfile(target):
                    remove(target)

    @staticmethod
    def list_pool():
        if go(['ls ' + Backup.pool_path + ' | cut -f 1 -d "." | sort | wc -l']) == '0':
            print(t.italic_yellow('There is no pools yet...'))
        else:
            print(t.blue(go(['ls ' + Backup.pool_path + ' | grep .pkl | cut -f 1 -d "." | sort'])))

    def list_db(self):
        if go(['ls {}{} | wc -l'.format(self.pool_path, self.pool['name'])]) == '0':
            print(t.italic_yellow('There is no databases in this pool yet...'))
        else:
            print(t.blue(go(['ls {}{} | sort'.format(self.pool_path, self.pool['name'])])))

    def list_backs(self):
        for db in self.db:
            if go(['ls {}{}{} | sort | wc -l'.format(self.pool_path, self.pool['name'], db)]) == '0':
                print(t.italic_yellow('There is no backups yet...'))
            else:
                backups = go(['ls {}{}/{} | sort | nl'.format(self.pool_path, self.pool['name'], db)])
                print(t.cyan('\n{}'.format(backups)))

                if len(self.db) == 1:
                    return [i.split('\t')[1] for i in backups.split('\n')]

    def create_pool(self):
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

            system('mkdir -p ' + Backup.pool_path + pool['name'])
            dump(Encoder().json_encode(pool), open(Backup.pool_path + pool['name'] + '.pkl', 'wb'))

            print(t.green('\nSuccessfully created pool named: ' + pool['name']))

            self._set_pool(pool['name'])
        except Exception:
            pass

    def _set_pool(self, name):
        try:
            if not name:
                self._args.print_help()
                exit(0)

            enc = Encoder()
            self.pool = {'name': name}

            self.pool = load(open(self.pool_path + self.pool['name'] + '.pkl', 'rb'))
            self.pool = enc.json_decode(self.pool)

        except Exception as e:
            print(t.red('There is no pool named: ' + self.pool['name'] + ', please add it'))
            exit(2)

        return self.pool

    def remove_pool(self):
        system('rm ' + self.pool_path + self.pool['name'] + '.pkl')
        system('rm -r ' + self.pool_path + self.pool['name'])

        print(t.green('Successfully removed: ' + self.pool['name']))

    def restore(self):
        backs = self.list_backs() if self.list_backs() else exit()
        print(t.blue('     {}\tOther...'.format(len(backs) + 1)))

        choice = int(input(t.yellow('\nMake your choice [{}]: '.format(len(backs)))) or len(backs))

        if choice > len(backs):
            _choice = input(t.yellow('\nType backup full path: '))
        else:
            _choice = '{}{}/{}/{}'.format(self.pool_path, self.pool['name'], self.db[0], backs[choice - 1])

        print(t.cyan('Restoring....'))

        bad = system(self.defs['engines'][self.pool['engine']]['restore'].format(db=self.db[0],
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

    def z_cleaner(self):
        print()
        for db in self.db:
            _path = self.pool_path + self.pool['name'] + '/' + db + '/'
            backups = go('ls ' + _path)
            backups = backups.split('\n')

            if len(backups) <= self.args.days:
                print(t.italic_yellow('The database ' + db + ' was already clean...'))
                continue

            ba = [datetime.strptime(x[-26:-7], '%d-%m-%YT%H:%M:%S') for x in backups]
            ba.sort()

            for x in ba[:-self.args.days]:
                target = '{}{}_{}.backup'.format(_path, db, x.strftime('%d-%m-%YT%H:%M:%S'))
                if self.pool['engine'] != 'mongodb':
                    remove(target)
                else:
                    rmtree(target)

        print(t.blue('\nDatabases cleaned...'))

    def _set_args(self):
        raw_args = ArgumentParser(description='This script handles backup/restore/auto-cleaning for multiple '
                                              'database engines')

        pools = raw_args.add_argument_group('Working with pools')
        _pools = pools.add_mutually_exclusive_group()
        _pools.add_argument('-cp', '--create-pool', dest='create_pool', action='store_true', help='Starts an interactive shell')
        _pools.add_argument('-lp', '--list-pools', dest='list_pool', action='store_true', help='Pool list')
        _pools.add_argument('-rp', '--remove-pool', dest='remove_pool', metavar='POOL', help='Delete pool')

        backups = raw_args.add_argument_group('Working with Backups')
        backups.add_argument('-p', '--pool', dest='pool_', metavar='NAME', help='Pool name')

        _backups = backups.add_mutually_exclusive_group()
        _backups.add_argument('-db', '--databases', dest='make', nargs='+', metavar='db', help='Spaced database names')
        _backups.add_argument('-a', '--all', dest='make', action='store_true', help='Get all databases for user')

        backups.add_argument('-c', '--clean', dest='z_cleaner', action='store_true', help='Auto clean backups history')
        backups.add_argument('-d', '--days', dest='days', default=5, type=int, help='History days to keep')
        backups.add_argument('--list-backups', dest='list_backs', action='store_true', help='Backup list')
        backups.add_argument('--list-db', dest='list_db', action='store_true', help='Database list')

        restore = raw_args.add_argument_group('Restore (requires -p and -db)')
        restore.add_argument('-r', '--restore', dest='restore', action='store_true', help='Restore backup')
        
        self._args = raw_args
        self.args = raw_args.parse_args()

    def _args_builder(self):
        self._set_args()

        if self.args.pool_ or self.args.remove_pool or self.args.make:
            self._set_pool(self.args.pool_ or self.args.remove_pool)

            if self.args.make:
                self._set_databases(self.args.make)

        [getattr(self, arg)() for arg in dir(self.args) if not arg.startswith('_') and getattr(self.args, arg) and getattr(self, arg, False)]


t = Terminal()

if __name__ == '__main__':
    Backup()

