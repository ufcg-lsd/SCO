credentials_path="/usr/src/credentials.tmp"
login=$(sed -n '1p' $credentials_path)
password=$(sed -n '2p' $credentials_path)
if [ -s ./credentials.tmp ]; then
    docker login -u $login -p $password
fi
rm $credentials_path

