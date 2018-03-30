# db-backup (backer)
Script en python para gestionar backups y restore de varios manejadores de Base de Datos (MySQL, PostgreSQL, MongoDB *por ahora)

```
backer usage: backer [ -ARGS ] [ VALUE ] [ -OPTIONS] 

              backer -p pool -db db 

              backer -p pool -db "db1 db2" 

              backer -p pool -db "db1 db2" --clean (for making and auto cleaning) 
              
              backer -p pool -db "db1 db2" --days n --clean

pools usage: backer [ -OPTIONS ] 

 -ARGS:
  -p, --pool: Pool name
  -db, --databases: Database names as follows -> name or "name1 name2" 

 -OPTIONS:
  -cp, --create-pool: Starts an interactive bash
  -lp, --list-pools: To get a list of pools
  -rp, --remove-pool: To remove a pool
  --list-db: List pool databases when used with --pool
  --list-backups: List database backups when used with -p and -db
  --clean: To clean a specified database or a list (-db "name1 name2")
  --restore: Interactive shell for restoring database when used with -p and -db
  -d, --days: if --clean is passed will set the last days to keep at cleaning
```
