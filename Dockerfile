# Build stage
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src

COPY AuthServer/AuthServer.csproj AuthServer/
RUN dotnet restore AuthServer/AuthServer.csproj

COPY . .
WORKDIR /src/AuthServer
RUN dotnet publish -c Release -o /app/out --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:6.0
WORKDIR /app

COPY --from=build /app/out .

ENV ASPNETCORE_URLS=http://+:80
EXPOSE 80

ENTRYPOINT ["dotnet", "AuthServer.dll"]
