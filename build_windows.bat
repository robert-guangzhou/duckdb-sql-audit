@echo off
REM build_windows.bat - MSVC build of sql_audit (multiplatform phase 1)
REM Follows ci-environment-experience.md section 3.1: no make on Windows,
REM must call cmake directly and replicate the BUILD_FLAGS four parameters.
REM Missing UNITTEST_ROOT_DIRECTORY leads to "No test cases matched" fake green.
setlocal enabledelayedexpansion

set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat
set VSCMAKE=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin
set VSNINJA=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja

set REPO=%~dp0
if "%REPO:~-1%"=="\" set REPO=%REPO:~0,-1%
REM D6 (handbook): backslash paths hit C-escape mangling (E:	 -> TAB,
REM secret_vault 0xC0000409 root cause). Always pass forward slashes to cmake.
set REPO_FS=%REPO:\=/%

call "%VCVARS%" x64 || exit /b 1
set PATH=%VSCMAKE%;%VSNINJA%;%PATH%

echo [1/3] cargo staticlib (x86_64-pc-windows-msvc)
%USERPROFILE%\.cargo\bin\cargo.exe build --release --target x86_64-pc-windows-msvc --manifest-path "%REPO%\rust\Cargo.toml" || exit /b 1
copy /Y "%REPO%\rust\target\x86_64-pc-windows-msvc\release\sql_audit.lib" "%REPO%\src\sql_audit.lib" >nul || exit /b 1

echo [2/3] cmake configure (four handbook parameters, generator-agnostic)
cmake -G Ninja ^
  -DEXTENSION_STATIC_BUILD=1 ^
  -DDUCKDB_EXTENSION_CONFIGS="%REPO_FS%/extension_config.cmake" ^
  -DUNITTEST_ROOT_DIRECTORY="%REPO_FS%" ^
  -DBENCHMARK_ROOT_DIRECTORY="%REPO_FS%" ^
  -DENABLE_UNITTEST_CPP_TESTS=FALSE ^
  -DENABLE_EXTENSION_AUTOLOADING=1 ^
  -DENABLE_EXTENSION_AUTOINSTALL=1 ^
  -DCMAKE_BUILD_TYPE=Release ^
  -S "%REPO%\duckdb" -B "%REPO%\build\win_release" || exit /b 1

echo [3/3] build extension + unittest + local extension repo
cmake --build "%REPO%\build\win_release" --target sql_audit_loadable_extension duckdb_local_extension_repo unittest || exit /b 1

echo BUILD OK
exit /b 0
