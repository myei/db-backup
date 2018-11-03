# db-backup (backer)
Script en python para gestionar backups y restore con auto-limpieza parametrizable de varios manejadores de Base de Datos (MySQL, PostgreSQL, MongoDB *por ahora)

```
usage: backer [-h] [-cp | -lp | -rp POOL] [-p NAME] [-db name [name ...] | -a]
              [-c] [-d DAYS] [--list-backups] [--list-db] [-r]

This script handles backup/restore/auto-cleaning for multiple database engines

optional arguments:
  -h, --help            show this help message and exit

Working with pools:
  -cp, --create-pool    Starts an interactive shell
  -lp, --list-pools     Pool list
  -rp POOL, --remove-pool POOL
                        Delete pool

Working with Backups:
  -p NAME, --pool NAME  Pool name
  -db name [name ...], --databases name [name ...]
                        Spaced database names
  -a, --all             Get all databases for user
  -c, --clean           Auto clean backups history
  -d DAYS, --days DAYS  History days to keep
  --list-backups        Backup list
  --list-db             Database list

Restore (requires -p and -db):
  -r, --restore         Restore backup

```
