first install postgress database and create the required database in it. Look in the application.properties for database name and also configure db credentials in environment variables as per the requirements of the application.properties file.

POST http://localhost:8080/auth/oauth/token
Headers:
Authorization: base64encoding(username:password)
Body:
form-data:
grant_type:client_credentials
scope:resource-server-read

GET http://localhost:9090
Headers:
Authorization: Bearer accesstoken