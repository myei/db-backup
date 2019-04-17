# db-backup (backer)

Script written in Python3 for database management that can do the following:

* Backup
* Restore
* Daily parameterizable backup files cleaning
* Account storage

Can work with:

* MySQL
* PostgreSQL
* MongoDB

```
usage: backer [-h] [-cp | -lp | -rp POOL] [-p NAME] [-db name [name ...] | -a]
              [-c] [-d DAYS] [--list-backups] [--list-db] [-r] [-v]

This script handles backup/restore/auto-cleaning for multiple database engines

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Shows script version

Working with pools:
  -cp, --create-pool    Starts an interactive shell
  -lp, --list-pools     Pool list
  -rp POOL, --remove-pool POOL
                        Delete pool

Working with Backups:
  -p NAME, --pool NAME  Pool name
  -db name [name ...], --databases name [name ...]
                        Spaced database names (requires -p)
  -a, --all             Get all databases for user (requires -p)
  -c, --clean           Auto clean backups history (requires -p and [-db |
                        -a])
  -d DAYS, --days DAYS  History days to keep (requires -c)
  --list-backups        Backup list (requires -p and [-db | -a])
  --list-db             Database list (requires -p)

Restore (requires -p and -db):
  -r, --restore         Restore backup

```

> In order to avoid security issues, it's highly recommended to obfuscate this script. I suggest to use ```pyminifier``` as follows:

```
pip3 install pyminifier
pyminifier --pyz backer backer.py
```
