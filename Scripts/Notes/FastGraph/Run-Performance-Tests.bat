@echo off
setlocal enabledelayedexpansion

echo Microsoft Extractor Suite - Performance Test Runner
echo ================================================
echo.

REM Check if PowerShell is available
powershell -Command "Write-Host 'PowerShell available'" >nul 2>&1
if errorlevel 1 (
    echo ERROR: PowerShell is not available or not in PATH
    pause
    exit /b 1
)

REM Set default values
set FUNCTION_NAME=Get-Users
set ITERATIONS=5
set OUTPUT_FILE=performance-results.csv
set TEST_BOTH=true

REM Parse command line arguments
:parse_args
if "%~1"=="" goto :run_tests
if /i "%~1"=="--function" (
    set FUNCTION_NAME=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--iterations" (
    set ITERATIONS=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--output" (
    set OUTPUT_FILE=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--csharp-only" (
    set TEST_BOTH=false
    shift
    goto :parse_args
)
if /i "%~1"=="--powershell-only" (
    set TEST_BOTH=false
    shift
    goto :parse_args
)
if /i "%~1"=="--help" goto :show_help
shift
goto :parse_args

:show_help
echo Usage: Run-Performance-Tests.bat [options]
echo.
echo Options:
echo   --function NAME     Function to test (default: Get-Users)
echo   --iterations N      Number of iterations (default: 5)
echo   --output FILE       Output CSV file (default: performance-results.csv)
echo   --csharp-only       Test only C# version
echo   --powershell-only   Test only PowerShell version
echo   --help             Show this help message
echo.
echo Examples:
echo   Run-Performance-Tests.bat --function Get-Groups --iterations 10
echo   Run-Performance-Tests.bat --function Get-UAL --csharp-only
echo   Run-Performance-Tests.bat --function Get-Users --output my-results.csv
echo.
pause
exit /b 0

:run_tests
echo Configuration:
echo   Function: %FUNCTION_NAME%
echo   Iterations: %ITERATIONS%
echo   Output: %OUTPUT_FILE%
echo   Test Both: %TEST_BOTH%
echo.

REM Run the PowerShell performance test
echo Starting performance test...
powershell -ExecutionPolicy Bypass -File "Quick-Performance-Test.ps1" -FunctionName "%FUNCTION_NAME%" -Iterations %ITERATIONS% -OutputFile "%OUTPUT_FILE%" -TestBoth %TEST_BOTH%

if errorlevel 1 (
    echo.
    echo ERROR: Performance test failed
    pause
    exit /b 1
)

echo.
echo Performance test completed successfully!
echo Results saved to: %OUTPUT_FILE%
echo.

REM Ask if user wants to open the results
set /p OPEN_RESULTS="Do you want to open the results file? (y/n): "
if /i "!OPEN_RESULTS!"=="y" (
    if exist "%OUTPUT_FILE%" (
        start "" "%OUTPUT_FILE%"
    ) else (
        echo Results file not found: %OUTPUT_FILE%
    )
)

pause
