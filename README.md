WhatsApp MultiDevice client

Literally everything combined from:
1. https://github.com/adiwajshing/baileys/tree/multi-device
2. https://github.com/tgalal/yowsup
3. https://github.com/sigalor/whatsapp-web-reveng
4. https://github.com/tulir/whatsmeow


Installation:
```shell
 git clone git@github.com:harianjalundu77/wamd.git
 cd wamd
 pip3 install -r requirements.txt
 python3 setup.py install --record install.txt
```

Or using venv:
```shell
python3 -m venv venv
git clone git@github.com:harianjalundu77/wamd.git
cd wamd
pip install -r requirements.txt
python setup.py install --record install.txt
```

Uninstall:
```shell
xargs rm -rf < install.txt
```

python3 set
Run the example:
```shell
python3 example.py
```
