# Как должно быть

### Ссылки
https://datatracker.ietf.org/doc/html/rfc7636
https://datatracker.ietf.org/doc/html/rfc6749

### Термины и определения
- code_verifier - случайное значение **секретное** для защиты authorization_code от перехвата. Длина от 43 до 128 символов в URL или 256 bits. Данный код должен быть уникальным для каждого запроса и перекодироваться с использованием code_challenge_method в code_challenge для отправки по сети
- code_challenge - закодированное с использованием code_challenge_method значение code_verifier. Способ получения 
`code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`
- code_challenge_method метод шифрования рекомендуется использовать S256 оно же sha256
- state - необязательный дополнительный параметр для защит от csrf атак, передается в первом запроса и должен быть уникальным для каждого запроса. Используется только для гарантии того что аутентификацию пытается провести пользователь. Также должен привязываться с сессии конкретного пользователя
- redirect_uri - адрес для возврата пользователя после успешной аутентификации
- client_id - клиентом в терминах keycloak является уникальное приложение 
- realm - виртуальное пространство в keycloak, внутри которого могут быть несколько клиентов (приложений)б=, либо одно приложение, но с разными схемами аутентификации

### Ограничения
code_verifier должно формироваться уникально для каждой аутентификации. Должно отправляться на IdP только в момент запроса токенов
Сервер IpD обязан осуществить проверку code_verifier перед отправкой токенов, проверка осуществляется путем аналогичного хеширования code_verifier с SHA256 в code_challenge и далее сравнивает их с ранее полученным значением
Для всех операций должен использоваться TLS \ DTLS
Не рекомендуется использовать plain code_challenge - когда не хешируется code_verifier.
На фронте не должны храниться и попадать authorization_code \ любые token

# Что проверять и как тестировать
Тест-кейс 1. Запрос у провайдера authorization_code
```sh
curl --location \
--get \
--url "https://{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth" \
--data-urlencode "response_type=code" \
--data-urlencode "redirect_uri=$REDIRECT_URI" \
--data-urlencode "client_id=$CLIENT_ID" \
--data-urlencode "code_challenge=$CODE_CHALLENGE" \
--data-urlencode "code_challenge_method=$CODE_CHALLENGE_METHOD"
```

Тест-кейс 2. Запрос токенов с кодом авторизации и с code_verifier (!ВАЖНО не code_challenge)
```sh
curl --request POST \
--url "https://{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token" \
--data-raw "authorization_code=$CODE&code_verifier=$CODE_VERIFIER"
```

Негативный тест-кейс 3. Проверка корректности state на бэке приложения через подмену callback_uri
1. Открыть консоль разработчика в браузере (DEVTOOLS)
2. Нажать Логин
3. Ввести корректные тестовые учетные данные. Пройти аутентификацию
4. В консоли найти callback_uri - скопировать запрос `http://your_app:8000/callback_auth_pkce?state=mwN9gAtlld0b_c-lSE...`
5. На выбор:
- через режим инкогнито вставить запрос и попробовать повторно воспользоваться им. Ожидаемый результат: ошибка
- через fetch запрос модифицировать значение state. Ожидаемый результат: ошибка
- возможность повторного использования state? Ожидаемый результат: ошибка
- связки сессии пользователя со значением state? Ожидаемый результат: ошибка

# В каких случаях (бизнес сценариях можно использовать)
- Веб приложения
- Приложения в недоверенной поверхности