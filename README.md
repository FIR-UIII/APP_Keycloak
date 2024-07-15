# README.md
Лаборатория APP_Keycloak для демонстрации работы методов аутентификации и авторизации с интеграцией в качестве IAM - KEYCLOAK (требуется отдельная установка), версия 24.0.3.

### Настройка и корректная работа стенда
1. Установка зависимостей: pip install -r requirements.txt
2. Настройка стенда KEYCLOAK в режиме DEV. 
3. Конфигурация - realm-export.json, где заданы параметры:
    * Название тенанта (realm): "web_app"
    * Адрес стенда: http://localhost:8000/ (изменить в realm KEYCLOAK)
4. Адрес KEYCLOAK: http://localhost:8080/ (изменить в .env @KEYCLOAK_URL)
5. Проверить и изменить при необходимости секреты и переменные окружения в файле: .example_env > заменить на .env и изменить параметры
6. Защищенная страница с доступом через access token для тестирования: /protected_page

### TODO (выполненные задачи):
1.  Реализация Grand type: Authorization code flow
2.  Реализация Grand type: Implicit code flow (LEGACY)
3.  Переход на модульную систему Blueprint
4.  Реализация Grand type: Client Credentials
5.  Реализация Grand type: Password / Resource Owner Password Flow (LEGACY)
6.  Реализация Grand type: Device Code
7.  Реализация Grand type: Authorization code flow + PKCE
8.  Сделать страницу для авторизации по access token /protected_page
9.  Функция logout – корректно завершать сессию клиента в каждом flow через id_token_hint
10. Единая точка хранения секретов для интеграцией с vault agent
11. Отдельная область стенда - добавить basic, digest, bearer token
12. JWT - проверка подписи, валидация (API key)




