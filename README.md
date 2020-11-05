h# GuardianBot

![](https://img.shields.io/cirrus/github/flutter/flutter) ![](https://img.shields.io/github/pipenv/locked/dependency-version/metabolize/rq-dashboard-on-heroku/flask)
![](https://img.shields.io/github/pipenv/locked/python-version/metabolize/rq-dashboard-on-heroku)

Cortafuegos de alto rendimiento basado en eBPF XDP. Interfaz web sencilla en Flask Python que permite aportar fácilmente soluciones mediante una API REST.
## Instalación
Cambia de usuario a root.
```bash
sudo su
```
Descarga una copia local del repositorio git.
```bash
git clone https://github.com/igallar98/GuardianBot.git
cd GuardianBot
```
Usa [python](https://www.python.org/) y el instalador de paquetes [pip](https://www.python.org/) para instalar las dependencias.

```bash
sudo apt install python3
sudo apt install python3-pip
```
Instala las dependencias.
```bash
pip3 install -r requirements.txt
```

Instala las dependencias de XDP.
```bash
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential net-tools
```
Compilación y creación de la contraseña maestra.
```bash
bash install.sh
```
## Uso
Para iniciar asegurese de que está en super usuario (sudo su).
```bash
bash start.sh
```
Accede a http://[IP]:4020 y usa la contraseña configurada en la instalación. La dirección IP puede ser la privada o la pública del servidor.

Para iniciar en modo manual en caso de que quira seleccionar la interfaz de forma manual:
```bash
cd xdp
sudo mount -t bpf bpf /sys/fs/bpf/
ulimit -l unlimited
sudo ./xdp_loader --auto-mode --dev [INTERFAZ] --force --progsec xdp_pass
sudo ./xdp_stats --dev [INTERFAZ] &
cd ../interface
sudo python3 run.py &
```
Cambiar [INTERFAZ] por la interfaz que desea usar.

## Contribuciones
Las solicitudes pull son bienvenidas. Para cambios importantes, abra un problema primero para discutir qué le gustaría cambiar.

Asegúrese de actualizar las pruebas según corresponda.

## Licencia
[MIT](https://choosealicense.com/licenses/mit/)
---------------------
