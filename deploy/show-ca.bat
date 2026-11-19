@echo off
REM ==============================================================================
REM show-ca.bat - exporte le certificat PUBLIC de la CA privee du HTTPS (jamais la cle)
REM ------------------------------------------------------------------------------
REM Cree "backos-ca.crt" a la racine du projet et affiche son empreinte SHA-256.
REM Sur chaque PC qui utilise l'application BACKOS Control : colle cette EMPREINTE dans les
REM parametres de l'application (Settings > serveur) apres l'avoir COMPAREE a celle affichee ici.
REM Le fichier .crt lui-meme n'est pas necessaire : l'application ne se fie qu'a l'empreinte.
REM ==============================================================================
cd /d "%~dp0.."
docker compose -f deploy\docker-compose.lan.yml --env-file .env.lan run --rm -T --no-deps tls-init print-ca > backos-ca.crt
if errorlevel 1 (
  echo.
  echo Echec : la pile LAN a-t-elle deja ete demarree au moins une fois ? ^(c'est elle qui cree la CA^)
  del backos-ca.crt 2>nul
) else (
  echo.
  echo Fichier ecrit : backos-ca.crt ^(certificat public, sans cle^)
)
pause
