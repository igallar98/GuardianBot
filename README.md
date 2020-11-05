# GuardianBot

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

Accede a 


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
---------------------
