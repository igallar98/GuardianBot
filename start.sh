#!/bin/bash

if [ "$(whoami)" != "root" ]; then
  echo "Vuelve a ejecutar el cortafuegos como root usando: sudo su"
  sudo su
else
  cd xdp
  sudo bash aux.sh
fi
