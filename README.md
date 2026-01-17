# VideoChat-v2
В новой версии добавлена HTTPS более стабильный WebSockets. 
Эту версию можно поместить на старый не нужный компьютер дома. 
Это делается с помощью переадресации портов. Покажу на примере Keenetic Air.
Перехоите на http://192.168.1.1 и попадаете в веб-конфигуратор. Имя и пароль : admin admin.
Переходим в сетевые правила --> переадресация портов --> новое правило.
Описание : любое.
Вход : Ethernet-подключение PPPoE.
Выход : Выберите название сервера.
Протокол : TCP/UDP.
Тип правила : Одиночный порт.
Открыть порт : Любой удобный.
Порт назначения : 8443.
Расписание работы : Любое удобное.
Всё! Запускаете video_server.py на сервере и ВСЁ!

# VideoChat-v2
The new version adds HTTPS and more stable WebSockets. 
You can install this version on an old computer you don't need at home. 
This is done using port forwarding. I'll show you the example of Keenetic Air.
Switch to http://192.168.1.1 and you get into the web configurator. Name and password : admin admin.
Go to network rules --> port forwarding --> new rule.
Description : any description.
Input : PPPoE Ethernet connection.
Exit: Select the server name.
Protocol : TCP/UDP.
Rule Type : Single port.
Open a port: Any convenient one.
Destination port : 8443.
Work schedule : Any convenient.
That's it! You are launching video_server.py on the server and THAT's IT!
# Как запустить?
Откройте терминал в папке с .py файлом (команда cd и путь)
И введите : python video_server.py.

# Устоновка библиотек.

```bash
python -m pip install --upgrade pip
pip install fastapi uvicorn websockets cryptography.
