FROM microsoft/dotnet:5.0-sdk as build

ARG BUILDCONFIG=RELEASE
AGR VERSION=1.0.0

COPY Tweetbook.csproj /build/

RUN dotnet restore ./build/Tweetbook.csproj

COPY . ./build/
WORKDIR /build/
RUN dotnet publish ./Tweetbook.csproj -c $BUILDCONFIG -o out /p:Version=$VERSION

FROM microsoft/dotnet:5.0-aspnetcore-runtime
WORKDIR /app

COPY --from-build /build/out

ENTRYPOINT ["dotnet", "Tweetbook.dll"]