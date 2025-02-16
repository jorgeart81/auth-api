# Develop
1. Install docker
2. Run database with docker: 
    ```dotnetcli
    docker compose up -d
    ```

# Production
1. Install docker
2. Build image: 
    ```dotnetcli
   docker build -t authapi:latest . 
    ```
3. Run docker compose: 
    ```dotnetcli
    docker compose -f docker-compose.prod.yml up
    ```

## Dotnet
 - Generate init.sql:
     ```dotnetcli
     dotnet ef migrations script --output init.sql
    ```
     