cd xdp
make
cd ../data
rm *.data
touch key.data
echo "Introduce la contraseña maestra del cortafuegos: "

python3 -c 'import crypt,getpass; print(crypt.crypt(getpass.getpass(), "gbot"))' >> mkey.data

