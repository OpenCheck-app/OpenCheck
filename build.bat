@echo off
rem Builds OpenCheck.exe on your own PC.
rem Needs the free .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0
cd /d "%~dp0"

where dotnet >nul 2>nul
if errorlevel 1 (
  echo The .NET SDK isn't installed. Get it from https://dotnet.microsoft.com/download/dotnet/8.0 and run this again.
  pause
  exit /b 1
)

echo Running tests...
dotnet test tests\PCCheck.Tests\PCCheck.Tests.csproj -c Release
if errorlevel 1 (
  echo.
  echo Tests failed. Nothing was built.
  pause
  exit /b 1
)

echo Building...
dotnet build src\PCCheck\PCCheck.csproj -c Release -o out
if errorlevel 1 (
  echo.
  echo Build failed.
  pause
  exit /b 1
)

echo.
echo Done. The app is in the "out" folder: out\OpenCheck.exe
echo Share the whole "out" folder (zip it). The .exe needs the WebView2 .dll files next to it.
pause
