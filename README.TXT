Besoin d'aide :
https://www.avhiral.com/forum
https://discord.gg/GP6p6jSH

    @@   @  @  @  @  @@@  @@@    @@   @
   @@@@  @  @  @  @   @   @  @  @@@@  @
   @  @  @  @  @@@@   @   @  @  @  @  @ 
   @@@@  @  @  @@@@   @   @@@   @@@@  @ 
   @  @  @  @  @  @   @   @  @  @  @  @
   @  @   @@   @  @  @@@  @  @  @  @  @@@ TE@M


AVHIRAL-GUARDIAN V2.4 LINUX

Changer par votre IP Publique dans cette partie en bas du code :

if __name__ == "__main__":
    public_ip = "VOTRE IP PUBLIQUE"  # Replace with your actual public IP
    guardian = Guardian(public_ip)
    if "--start" in sys.argv:
        guardian.start()
    elif "--stop" in sys.argv:
        subprocess.run(["systemctl", "stop", "guardian.service"])
    elif "--status" in sys.argv:
        print("Guardian is active." if guardian.active else "Guardian is not active.")

------------------------------------------------------------------------------------------

Tutoriel pour installer Python 3 sur Debian et Ubuntu
Suivez ces étapes pour installer Python 3 sur votre système Debian ou Ubuntu.

Prérequis
Un système Debian ou Ubuntu.
Accès à un terminal avec des privilèges sudo.
Étape 1 : Mettre à jour les paquets
Avant d'installer Python 3, il est recommandé de mettre à jour la liste des paquets disponibles et les paquets installés sur votre système. Ouvrez un terminal et exécutez les commandes suivantes :

sudo apt update
sudo apt upgrade
Étape 2 : Installer Python 3
Debian et Ubuntu incluent Python 3 dans leurs dépôts par défaut. Pour installer Python 3, utilisez la commande suivante :

sudo apt install python3
Étape 3 : Vérifier l'installation de Python 3
Une fois l'installation terminée, vérifiez que Python 3 est correctement installé en vérifiant sa version :

python3 --version
Vous devriez voir une sortie similaire à celle-ci, indiquant que Python 3 est installé avec succès :

Python 3.x.x
Étape 4 : Installer pip pour Python 3
pip est l'outil de gestion de paquets pour Python. Il est souvent utilisé pour installer et gérer des bibliothèques Python. Pour installer pip pour Python 3, exécutez la commande suivante :

sudo apt install python3-pip
Étape 5 : Vérifier l'installation de pip
Après l'installation, vous pouvez vérifier que pip est correctement installé en vérifiant sa version :

pip3 --version
Vous devriez voir une sortie similaire à celle-ci, indiquant que pip est installé avec succès :

pip 21.0.1 from /usr/lib/python3/dist-packages/pip (python 3.x)

INSTALLATION GUARDIAN V2.3 :


sudo nano /etc/systemd/system/guardian.service

Pour python2 :

----------------------------------------------------------------------------------------------------

[Unit]
Description=Guardian Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python2 /root/guardian23/guardian_v2.3_linux.py --start
Restart=always

[Install]
WantedBy=multi-user.target

----------------------------------------------------------------------------------------------------

Pour python3 :

----------------------------------------------------------------------------------------------------

[Unit]
Description=Guardian Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/guardian23/guardian_v2.3_linux.py --start
Restart=always

[Install]
WantedBy=multi-user.target

----------------------------------------------------------------------------------------------------

Créer répertoire guardian23/ dans root/ et copier le fichier guardian_v2.3_linux.py dans guardian23/

----------------------------------------------------------------------------------------------------

Installation :
sudo systemctl daemon-reload
sudo systemctl enable guardian.service
sudo systemctl start guardian.service
sudo systemctl status guardian.service

Système actif et OK :

sudo systemctl status guardian.service
● guardian.service - Guardian Service
     Loaded: loaded (/etc/systemd/system/guardian.service; enabled; vendor preset: enabled)
     Active: active (running) since Sun 2024-05-19 18:53:37 CEST; 10min ago
   Main PID: 324505 (python3)
      Tasks: 6 (limit: 5724)
     Memory: 14.0M
     CGroup: /system.slice/guardian.service
             ├─324505 /usr/bin/python3 /root/guardian23/guardian_v2.3_linux.py --start
             ├─338461 sudo iptables -A INPUT -s 104.238.188.62 -j DROP
             └─338464 iptables -A INPUT -s 104.238.188.62 -j DROP

mai 19 19:03:41 avhiral-MS-7369 sudo[338455]: pam_unix(sudo:session): session opened for user root by (uid=0)
mai 19 19:03:41 avhiral-MS-7369 sudo[338455]: pam_unix(sudo:session): session closed for user root
mai 19 19:03:41 avhiral-MS-7369 sudo[338457]:     root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/iptables -A INPUT -s 70.34.221.133 -j DROP
mai 19 19:03:41 avhiral-MS-7369 sudo[338457]: pam_unix(sudo:session): session opened for user root by (uid=0)
mai 19 19:03:41 avhiral-MS-7369 sudo[338457]: pam_unix(sudo:session): session closed for user root
mai 19 19:03:41 avhiral-MS-7369 sudo[338459]:     root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/iptables -A INPUT -s 45.77.13.189 -j DROP
mai 19 19:03:41 avhiral-MS-7369 sudo[338459]: pam_unix(sudo:session): session opened for user root by (uid=0)
mai 19 19:03:41 avhiral-MS-7369 sudo[338459]: pam_unix(sudo:session): session closed for user root
mai 19 19:03:41 avhiral-MS-7369 sudo[338461]:     root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/iptables -A INPUT -s 104.238.188.62 -j DROP
mai 19 19:03:41 avhiral-MS-7369 sudo[338461]: pam_unix(sudo:session): session opened for user root by (uid=0)

Commandes :

sudo systemctl daemon-reload
sudo systemctl enable guardian.service
sudo systemctl start guardian.service
sudo systemctl status guardian.service
sudo journalctl -u guardian.service


