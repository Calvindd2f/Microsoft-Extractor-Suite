@echo off

rem Set the path to the current directory
pushd %~dp0

rem Command file for Sphinx documentation

rem Check if SPHINXBUILD is set, if not set it to sphinx-build
if not defined SPHINXBUILD (
    set "SPHINXBUILD=sphinx-build"
)

rem Set the source and build directories
set "SOURCEDIR=source"
set "BUILDDIR=build"

rem Check if a command was provided as an argument
if "%~1" == "" (
    goto help
)

rem Check if sphinx-build is installed
%SPHINXBUILD% >nul 2>nul
if errorlevel 9009 (
    echo.
    echo.The 'sphinx-build' command was not found. Make sure you have Sphinx
    echo.installed, then set the SPHINXBUILD environment variable to point
    echo.to the full path of the 'sphinx-build' executable. Alternatively you
    echo.may add the Sphinx directory to PATH.
    echo.
    echo.If you don't have Sphinx installed, grab it from
    echo.http://sphinx-doc.org/
    exit /b 1
)

rem Build the documentation
%SPHINXBUILD% -M %1 %SOURCEDIR% %BUILDDIR% %SPHINXOPTS% %O%

rem Go to the end label
goto end

:help
rem Show the help message
%SPHINXBUILD% -M help %SOURCEDIR% %BUILDDIR% %SPHINXOPTS% %O%

:end
rem Go back to the previous directory
popd
