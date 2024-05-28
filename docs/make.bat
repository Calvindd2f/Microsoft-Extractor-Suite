@echo off

rem Set the path to the current directory
pushd %~dp0

rem Command file for Sphinx documentation

rem Check if SPHINXBUILD is set, if not set it to sphinx-build (with full path)
if not defined SPHINXBUILD (
    set "SPHINXBUILD=C:\Python39\Scripts\sphinx-build.exe"
    if not exist "%SPHINXBUILD%" (
        echo.
        echo.The 'sphinx-build' command was not found. Make sure you have Sphinx
        echo.installed, then set the SPHINXBUILD environment variable to point
        echo.to the full path of the 'sphinx-build' executable.
        echo.
        exit /b 1
    )
)

rem Set the source and build directories
set "SOURCEDIR=source"
set "BUILDDIR=build"

rem Check if a command was provided as an argument
if "%~1" == "" (
    goto help
)

rem Check if sphinx-build is installed and executable
if not exist "%SPHINXBUILD%" (
    echo.
    echo.The 'sphinx-build' command was not found. Make sure you have Sphinx
    echo.installed, then set the SPHINXBUILD environment variable to point
    echo.to the full path of the 'sphinx-build' executable.
    echo.
    exit /b 1
) else (
    "%SPHINXBUILD%" -V >nul 2>nul
    if errorlevel 1 (
        echo.
        echo.The 'sphinx-build' command is not executable. Make sure the
        echo.SPHINXBUILD environment variable points to the correct location.
        echo.
        exit /b 1
    )
)

rem Build the documentation
"%SPHINXBUILD%" -M %1 %SOURCEDIR% %BUILDDIR% %SPHINXOPTS% %O%

rem Go to the end label
goto end

:help
rem Show the help message
"%SPHINXBUILD%" -M help %SOURCEDIR% %BUILDDIR% %SPHINXOPTS% %O%

:end
rem Go back to the previous directory
popd

