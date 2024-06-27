Function Log([string]$log, [bool]$show=$true)
{
    [string]$logtime = $((Get-Date -Format "[dd/MM/yyyy HH:mm:ss zz] |").ToString())
    foreach ($line in $($log -split "`n"))
    {
        if ($VerbosePreference -eq 'Continue' -or $show -eq $true) { [console]::WriteLine("$logtime $line") }
        #Add-Content -Path "C:\Windows\Temp\agent.log" -Value "$logtime $line"
        # Append log entry to the log file using StreamWriter
        $logFile = "C:\Windows\Temp\agent.log"
        $logEntry = "$logtime $line"
        $StreamWriter = New-Object System.IO.StreamWriter($logFile, $true)
        try {
            $StreamWriter.WriteLine($logEntry)
        }
        catch {
            [console]::WriteLine("1/2 | Error writing to log file.");
            [console]::WriteLine("1/2 | Creating the log file then retrying.");
            if([string]::IsNullOrEmpty($logFile))
            {
                New-Item -ItemType File -Name activity.log > $null
            }

            try
            {
                $StreamWriter.WriteLine($logEntry)
            }
            catch
            {
                [console]::WriteLine("2/2 | Error writing to log file");
                throw [System.Exception]::new().Message('Critical Exception Thrown.')
                [exit]0
            }
            finally
            {
                $StreamWriter.Close()
            }
        }
        finally {
            $StreamWriter.Close()
        }
    }
}
enum logtype
{
    INFO
    ERROR
    WARNING
    DEBUG
    FATAL
}
