param ($TenantID,
        $Appid,
        $SubscriptionID,
        $Secret, 
        $ResourceGroup, 
        [switch]$Debug, 
        [switch]$SkipMetrics, 
        [switch]$SkipConsumption, 
        [switch]$DeviceLogin,
        [switch]$EnableLogs,
        $ConcurrencyLimit = 6,
        $ReportName = 'ResourcesReport', 
        $OutputDirectory)


if ($Debug.IsPresent) {$DebugPreference = 'Continue'}

if ($Debug.IsPresent) {$ErrorActionPreference = "Continue" }Else {$ErrorActionPreference = "silentlycontinue" }

Write-Debug ('Debbuging Mode: On. ErrorActionPreference was set to "Continue", every error will be presented.')

Function Write-Log([string]$Message, [string]$Severity)
{
   $DateTime = "[{0:dd-MM-yyyy} {0:HH:mm:ss}]" -f (Get-Date)

   if($EnableLogs.IsPresent)
   {
        $Global:Logging.Logs.Add([PSCustomObject]@{ Date = $DateTime; Message = $Message; Severity = $Severity })
   }

   switch ($Severity) 
   {
        "Info"    { Write-Host $Message -ForegroundColor Cyan }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error"   { Write-Host $Message -ForegroundColor Red }
        "Success"   { Write-Host $Message -ForegroundColor Green }
        default   { Write-Host $Message }
    }
}

function GetLocalVersion() 
{
    $versionJsonPath = "./Version.json"
    if (Test-Path $versionJsonPath) 
    {
        $localVersionJson = Get-Content $versionJsonPath | ConvertFrom-Json
        return ('{0}.{1}.{2}' -f $localVersionJson.MajorVersion, $localVersionJson.MinorVersion, $localVersionJson.BuildVersion)
    } 
    else 
    {
        Write-Host "Local Version.json not found. Clone the repo and execute the script from the root. Exiting." -ForegroundColor Red
        Exit
    }
}

function Variables 
{
    $Global:ResourceContainers = @()
    $Global:Resources = @()
    $Global:Subscriptions = ''
    $Global:ReportName = $ReportName   
    $Global:Version = GetLocalVersion

    $Global:Logging = New-Object PSObject
    $Global:Logging | Add-Member -MemberType NoteProperty -Name Logs -Value NotSet
    $Global:Logging.Logs = [System.Collections.Generic.List[object]]::new()


    $Global:RawRepo = 'https://raw.githubusercontent.com/awslabs/resource-discovery-for-azure/main'
    $Global:TableStyle = "Medium15"
}

Function RunInventorySetup()
{
    function CheckVersion()
    {
        Write-Log -Message ('Checking Version') -Severity 'Info'
        Write-Log -Message ('Version: {0}' -f $Global:Version) -Severity 'Info'
        
        $versionJson = (New-Object System.Net.WebClient).DownloadString($RawRepo + '/Version.json') | ConvertFrom-Json
        $versionNumber = ('{0}.{1}.{2}' -f $versionJson.MajorVersion, $versionJson.MinorVersion, $versionJson.BuildVersion)

        if($versionNumber -ne $Global:Version)
        {
            Write-Log -Message ('New Version Available: {0}.{1}.{2}' -f $versionJson.MajorVersion, $versionJson.MinorVersion, $versionJson.BuildVersion) -Severity 'Warning'
            Write-Log -Message ('Download or Clone the latest version and run again: https://github.com/awslabs/resource-discovery-for-azure') -Severity 'Error'
            Exit
        }
    }

    function CheckPowerShell() 
    {
        Write-Log -Message ('Checking PowerShell...') -Severity 'Info'
    
        $Global:PlatformOS = 'PowerShell Desktop'
        $cloudShell = try{Get-CloudDrive}catch{}

        $Global:CurrentDateTime = (get-date -Format "yyyyMMddHHmm")
        $Global:FolderName = $Global:ReportName + $CurrentDateTime
        
        if ($cloudShell) 
        {
            Write-Log -Message ('Identified Environment as Azure CloudShell') -Severity 'Success'
            $Global:PlatformOS = 'Azure CloudShell'
            $defaultOutputDir = "$HOME/InventoryReports/" + $Global:FolderName + "/"
        }
        elseif ($PSVersionTable.Platform -eq 'Unix') 
        {
            Write-Log -Message ('Identified Environment as PowerShell Unix') -Severity 'Success'
            $Global:PlatformOS = 'PowerShell Unix'
            $defaultOutputDir = "$HOME/InventoryReports/" + $Global:FolderName + "/"
        }
        else 
        {
            Write-Log -Message ('Identified Environment as PowerShell Desktop') -Severity 'Success'
            $Global:PlatformOS= 'PowerShell Desktop'
            $defaultOutputDir = "C:\InventoryReports\" + $Global:FolderName + "\"

            $psVersion = $PSVersionTable.PSVersion.Major
            Write-Log -Message ("PowerShell Version {0}" -f $psVersion) -Severity 'Info'
        
            if ($PSVersionTable.PSVersion.Major -lt 7) 
            {
                Write-Log -Message ("You must use Powershell 7 to run the inventory script.") -Severity 'Error'
                Write-Log -Message ("https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3") -Severity 'Error'
                Exit
            }
        }
    
        if ($OutputDirectory) 
        {
            try 
            {
                $OutputDirectory = Join-Path (Resolve-Path $OutputDirectory -ErrorAction Stop) ('/' -or '\')
            }
            catch 
            {
                Write-Log -Message ("Wrong OutputDirectory Path! OutputDirectory Parameter must contain the full path.") -Severity 'Error'
                Exit
            }
        }
    
        $Global:DefaultPath = if($OutputDirectory) {$OutputDirectory} else {$defaultOutputDir}
    
        if ($platformOS -eq 'Azure CloudShell') 
        {
            $Global:Subscriptions = @(az account list --output json --only-show-errors | ConvertFrom-Json)
        }
        elseif ($platformOS -eq 'PowerShell Unix' -or $platformOS -eq 'PowerShell Desktop') 
        {
            LoginSession
        }
    }
    
  function LoginSession() 
    {        
        $CloudEnv = az cloud list | ConvertFrom-Json
        Write-Host "Azure Cloud Environment: " -NoNewline
    
        $CurrentCloudEnvName = $CloudEnv | Where-Object {$_.isActive -eq 'True'}
        Write-Host $CurrentCloudEnvName.name -ForegroundColor Green
    
        if (!$TenantID) 
        {
            Write-Log -Message ('Tenant ID not specified. Use -TenantID parameter if you want to specify directly.') -Severity 'Warning'
            Write-Log -Message ('Authenticating Azure') -Severity 'Info'
    
            Write-Log -Message ('Clearing account cache') -Severity 'Info'
            az account clear | Out-Null
            Write-Log -Message ('Calling Login, the browser will open and prompt you to login.') -Severity 'Info'

            $DebugPreference = "SilentlyContinue"
    
            if($DeviceLogin.IsPresent)
            {
                Write-Log -Message ('Using device login') -Severity 'Info'
                az login --use-device-code
                Connect-AzAccount -UseDeviceAuthentication | Out-Null
            }
            else 
            {
                Write-Log -Message ('Using device login') -Severity 'Info'
                az login --only-show-errors | Out-Null
                Connect-AzAccount | Out-Null
            }

            $DebugPreference = "Continue"
    
            $Tenants = @(az account list --query [].homeTenantId -o tsv --only-show-errors 2>$null | Sort-Object -Unique)

            Write-Log -Message ('Checking number of Tenants') -Severity 'Info'

            if ($Tenants.Count -eq 0 -or [string]::IsNullOrWhiteSpace($Tenants[0]))
            {
                Write-Log -Message ('Login failed or no accounts. Run: az logout then az login') -Severity 'Error'
                Exit
            }
    
            if ($Tenants.Count -eq 1) 
            {
                Write-Log -Message ('You have privileges only in One Tenant') -Severity 'Success'
                $TenantID = if ($Tenants -is [array]) { $Tenants[0] } else { $Tenants }
            }
            else 
            {
                Write-Log -Message ('Select the the Azure Tenant ID that you want to connect: ') -Severity 'Warning'
    
                $SequenceID = 1
                foreach ($t in $Tenants) 
                {
                    write-host "$SequenceID)  $t"
                    $SequenceID ++
                }
    
                $inputTenant = read-host "Select Tenant (Default 1)"
                [int]$SelectTenant = if ([string]::IsNullOrWhiteSpace($inputTenant)) { 1 } else { $inputTenant }
                if ($SelectTenant -lt 1) { $SelectTenant = 1 }
                $defaultTenant = [Math]::Min($SelectTenant - 1, $Tenants.Count - 1)
                $TenantID = $Tenants[$defaultTenant]
    
                if ([string]::IsNullOrWhiteSpace($TenantID))
                {
                    Write-Log -Message ('No tenant selected. Run: az logout then az login') -Severity 'Error'
                    Exit
                }
                if($DeviceLogin.IsPresent)
                {
                    az login --use-device-code -t $TenantID
                    Connect-AzAccount -UseDeviceAuthentication -Tenant $TenantID | Out-Null
                }
                else 
                {
                    az login -t $TenantID --only-show-errors | Out-Null
                    Connect-AzAccount -Tenant $TenantID | Out-Null
                }
            }
    
            Write-Log -Message ("Extracting from Tenant $TenantID") -Severity 'Info'
            Write-Log -Message ("Extracting Subscriptions") -Severity 'Info'
    
            $Global:Subscriptions = @(az account list --output json --only-show-errors | ConvertFrom-Json)
            $Global:Subscriptions = @($Subscriptions | Where-Object { $_.tenantID -eq $TenantID })
        }
        else 
        {
            az account clear | Out-Null
    
            if (!$Appid) 
            {
                if($DeviceLogin.IsPresent)
                {
                    az login --use-device-code -t $TenantID
                    Connect-AzAccount -UseDeviceAuthentication -Tenant $TenantID | Out-Null
                }
                else 
                {
                    az login -t $TenantID --only-show-errors | Out-Null
                    Connect-AzAccount -Tenant $TenantID | Out-Null
                }
            }
            elseif ($Appid -and $Secret -and $tenantid) 
            {
                Write-Log -Message ("Using Service Principal Authentication Method") -Severity 'Success'
                az login --service-principal -u $appid -p $secret -t $TenantID | Out-Null
            }
            else
            {
                Write-Log -Message ("You are trying to use Service Principal Authentication Method in a wrong way.") -Severity 'Error'
                Write-Log -Message ("It's Mandatory to specify Application ID, Secret and Tenant ID in Azure Resource Inventory") -Severity 'Error'
                Write-Log -Message (".\ResourceInventory.ps1 -appid <SP AppID> -secret <SP Secret> -tenant <TenantID>") -Severity 'Error'
                Exit
            }
    
            $Global:Subscriptions = @(az account list --output json --only-show-errors | ConvertFrom-Json)
            $Global:Subscriptions = @($Subscriptions | Where-Object { $_.tenantID -eq $TenantID })
        }
    }
    
    function GetSubscriptionsData()
    {    
        $SubscriptionCount = $Subscriptions.Count
        
        Write-Log -Message ("Number of Subscriptions Found: {0}" -f $SubscriptionCount) -Severity 'Info'
        Write-Log -Message ("Checking report folder: {0}" -f $DefaultPath) -Severity 'Info'
        
        if ((Test-Path -Path $DefaultPath -PathType Container) -eq $false) 
        {
            New-Item -Type Directory -Force -Path $DefaultPath | Out-Null
        }
    }
    
    function ResourceInventoryLoop()
    {
        # #region agent log
        $dbgLog = 'c:\GitHub\resource-discovery-for-azure\.cursor\debug.log'; $branch = 'none'; if (![string]::IsNullOrEmpty($ResourceGroup) -and ![string]::IsNullOrEmpty($SubscriptionID)) { $branch = 'ResourceGroupAndSub' } elseif ([string]::IsNullOrEmpty($ResourceGroup) -and ![string]::IsNullOrEmpty($SubscriptionID)) { $branch = 'SubOnly' } else { $branch = 'elseFullTenant' }; [System.IO.File]::AppendAllText($dbgLog, ((@{timestamp=[long](((Get-Date)-(Get-Date '1/1/1970')).TotalMilliseconds);location='ResourceInventory.ps1:ResourceInventoryLoop';message='ResourceInventoryLoop entry';data=@{branch=$branch};sessionId='debug-session';hypothesisId='H3'}|ConvertTo-Json -Compress)+"`n"))
        # #endregion
        if(![string]::IsNullOrEmpty($ResourceGroup) -and [string]::IsNullOrEmpty($SubscriptionID))
        {
            Write-Log -Message ("Resource Group Name present, but missing Subscription ID.") -Severity 'Error'
            Write-Log -Message ("If using ResourceGroup parameter you must also put SubscriptionId") -Severity 'Error'
            Exit
        }

        if(![string]::IsNullOrEmpty($ResourceGroup))
        {
           $ResourceGroup = $ResourceGroup.ToLower()
        }

        if(![string]::IsNullOrEmpty($ResourceGroup) -and ![string]::IsNullOrEmpty($SubscriptionID))
        {
            Write-Log -Message ('Extracting Resources from Subscription: ' + $SubscriptionID + '. And from Resource Group: ' + $ResourceGroup) -Severity 'Success'

            $Subscri = $SubscriptionID

            $GraphQuery = "resources | where resourceGroup == '$ResourceGroup' and strlen(properties.definition.actions) < 123000 | summarize count()"
            $EnvSize = az graph query -q $GraphQuery --subscriptions $Subscri --output json --only-show-errors | ConvertFrom-Json
            $EnvSizeNum = $EnvSize.data.'count_'

            if ($EnvSizeNum -ge 1) {
                $Loop = $EnvSizeNum / 1000
                $Loop = [math]::ceiling($Loop)
                $Looper = 0
                $Limit = 0

                while ($Looper -lt $Loop) {
                    $GraphQuery = "resources | where resourceGroup == '$ResourceGroup' and strlen(properties.definition.actions) < 123000 | project id,name,type,tenantId,kind,location,resourceGroup,subscriptionId,managedBy,sku,plan,properties,identity,zones,extendedLocation,tags | order by id asc"
                    $Resource = (az graph query -q $GraphQuery --subscriptions $Subscri --skip $Limit --first 1000 --output json --only-show-errors).tolower() | ConvertFrom-Json

                    $Global:Resources += $Resource.data
                    Start-Sleep 2
                    $Looper ++
                    $Limit = $Limit + 1000
                }
            }
        }
        elseif([string]::IsNullOrEmpty($ResourceGroup) -and ![string]::IsNullOrEmpty($SubscriptionID))
        {
            Write-Log -Message ('Extracting Resources from Subscription: ' + $SubscriptionID) -Severity 'Success'

            $GraphQuery = "resources | where strlen(properties.definition.actions) < 123000 | summarize count()"
            $EnvSize = az graph query -q $GraphQuery  --output json --subscriptions $SubscriptionID --only-show-errors | ConvertFrom-Json
            $EnvSizeNum = $EnvSize.data.'count_'

            if ($EnvSizeNum -ge 1) {
                $Loop = $EnvSizeNum / 1000
                $Loop = [math]::ceiling($Loop)
                $Looper = 0
                $Limit = 0

                while ($Looper -lt $Loop) {
                    $GraphQuery = "resources | where strlen(properties.definition.actions) < 123000 | project id,name,type,tenantId,kind,location,resourceGroup,subscriptionId,managedBy,sku,plan,properties,identity,zones,extendedLocation,tags | order by id asc"
                    $Resource = (az graph query -q $GraphQuery --subscriptions $SubscriptionID --skip $Limit --first 1000 --output json --only-show-errors).tolower() | ConvertFrom-Json

                    $Global:Resources += $Resource.data
                    Start-Sleep 2
                    $Looper ++
                    $Limit = $Limit + 1000
                }
            }
        } 
        else 
        {
            $GraphQuery = "resources | where strlen(properties.definition.actions) < 123000 | summarize count()"
            $subIds = @($Subscriptions | ForEach-Object { $_.id })
            # #region agent log
            $dbgLog = 'c:\GitHub\resource-discovery-for-azure\.cursor\debug.log'; [System.IO.File]::AppendAllText($dbgLog, ((@{timestamp=[long](((Get-Date)-(Get-Date '1/1/1970')).TotalMilliseconds);location='ResourceInventory.ps1:beforeAzGraph';message='before az graph query';data=@{subCount=$subIds.Count};sessionId='debug-session';hypothesisId='H1'}|ConvertTo-Json -Compress)+"`n"))
            # #endregion
            $azJob = Start-Job -ScriptBlock { param($q, $subs) az graph query -q $q --subscriptions $subs --output json --only-show-errors } -ArgumentList $GraphQuery, $subIds
            $completed = Wait-Job $azJob -Timeout 90
            if (-not $completed) {
                Stop-Job $azJob -ErrorAction SilentlyContinue; Remove-Job $azJob -Force -ErrorAction SilentlyContinue
                Write-Log -Message 'az graph query timed out (90s). Ensure resource-graph extension is installed: az extension add --name resource-graph' -Severity 'Error'
                Exit
            }
            $rawOut = Receive-Job $azJob; Remove-Job $azJob -Force -ErrorAction SilentlyContinue
            if ($rawOut -is [array]) { $rawOut = $rawOut -join "`n" }
            $EnvSize = $rawOut | ConvertFrom-Json
            # #region agent log
            $dbgLog = 'c:\GitHub\resource-discovery-for-azure\.cursor\debug.log'; $countVal = $null; try { $countVal = $EnvSize.Data.'count_' } catch {}; [System.IO.File]::AppendAllText($dbgLog, ((@{timestamp=[long](((Get-Date)-(Get-Date '1/1/1970')).TotalMilliseconds);location='ResourceInventory.ps1:afterAzGraph';message='after az graph query';data=@{EnvSizeCount=$countVal;EnvSizeNull=($null -eq $EnvSize)};sessionId='debug-session';hypothesisId='H2';hypothesisId2='H5'}|ConvertTo-Json -Compress)+"`n"))
            # #endregion
            $EnvSizeCount = $EnvSize.Data.'count_'
            
            Write-Log -Message ("Resources Output: {0} Resources Identified" -f $EnvSizeCount) -Severity 'Success'
            
            if ($EnvSizeCount -ge 1) 
            {
                $Loop = $EnvSizeCount / 1000
                $Loop = [math]::Ceiling($Loop)
                $Looper = 0
                $Limit = 0
            
                while ($Looper -lt $Loop) 
                {
                    $GraphQuery = "resources | where strlen(properties.definition.actions) < 123000 | project id,name,type,tenantId,kind,location,resourceGroup,subscriptionId,managedBy,sku,plan,properties,identity,zones,extendedLocation,tags | order by id asc"
                    $Resource = (az graph query -q $GraphQuery --subscriptions $subIds --skip $Limit --first 1000 --output json --only-show-errors).tolower() | ConvertFrom-Json
                    
                    $Global:Resources += $Resource.Data
                    Start-Sleep 2
                    $Looper++
                    $Limit = $Limit + 1000
                }
            }
        }
    }
    
    function ResourceInventoryAvd()
    {
        # #region agent log
        $dbgLog = 'c:\GitHub\resource-discovery-for-azure\.cursor\debug.log'; [System.IO.File]::AppendAllText($dbgLog, ((@{timestamp=[long](((Get-Date)-(Get-Date '1/1/1970')).TotalMilliseconds);location='ResourceInventory.ps1:ResourceInventoryAvd';message='ResourceInventoryAvd entry';data=@{};sessionId='debug-session';hypothesisId='H4'}|ConvertTo-Json -Compress)+"`n"))
        # #endregion
        $AVDSize = az graph query -q "desktopvirtualizationresources | summarize count()" --output json --only-show-errors | ConvertFrom-Json
        $AVDSizeCount = $AVDSize.data.'count_'
    
        Write-Host ("AVD Resources Output: {0} AVD Resources Identified" -f $AVDSizeCount) -BackgroundColor Black -ForegroundColor Green
    
        if ($AVDSizeCount -ge 1) 
        {
            $Loop = $AVDSizeCount / 1000
            $Loop = [math]::ceiling($Loop)
            $Looper = 0
            $Limit = 0
    
            while ($Looper -lt $Loop) 
            {
                $GraphQuery = "desktopvirtualizationresources | project id,name,type,tenantId,kind,location,resourceGroup,subscriptionId,managedBy,sku,plan,properties,identity,zones,extendedLocation,tags | order by id asc"
                $AVD = (az graph query -q $GraphQuery --skip $Limit --first 1000 --output json --only-show-errors).tolower() | ConvertFrom-Json
    
                $Global:Resources += $AVD.data
                Start-Sleep 2
                $Looper++
                $Limit = $Limit + 1000
            }
        } 
    }

    CheckVersion
    CheckPowerShell
    GetSubscriptionsData
    # #region agent log
    $dbgLog = 'c:\GitHub\resource-discovery-for-azure\.cursor\debug.log'; [System.IO.File]::AppendAllText($dbgLog, ((@{timestamp=[long](((Get-Date)-(Get-Date '1/1/1970')).TotalMilliseconds);location='ResourceInventory.ps1:RunInventorySetup';message='after GetSubscriptionsData before ResourceInventoryLoop';data=@{};sessionId='debug-session';hypothesisId='H3'}|ConvertTo-Json -Compress)+"`n"))
    # #endregion
    ResourceInventoryLoop
    ResourceInventoryAvd
}

function ExecuteInventoryProcessing()
{
    function InitializeInventoryProcessing()
    {   
        $Global:ZipOutputFile = ($DefaultPath + $Global:ReportName + "_" + $CurrentDateTime + ".zip")
        $Global:File = ($DefaultPath + $Global:ReportName + "_" + $CurrentDateTime + ".xlsx")
        $Global:AllResourceFile = ($DefaultPath + "Full_" + $Global:ReportName + "_" + $CurrentDateTime + ".json")
        $Global:JsonFile = ($DefaultPath + "Inventory_"+ $Global:ReportName + "_" + $CurrentDateTime + ".json")
        $Global:MetricsJsonFile = ($DefaultPath + "Metrics_"+ $Global:ReportName + "_" + $CurrentDateTime + ".json")
        $Global:ConsumptionFile = ($DefaultPath + "Consumption_"+ $Global:ReportName + "_" + $CurrentDateTime + ".json")
        $Global:ConsumptionFileCsv = ($DefaultPath + "Consumption_"+ $Global:ReportName + "_" + $CurrentDateTime + ".csv")

        $Global:LogFile = ($DefaultPath + "Logs_"+ $Global:ReportName + "_" + $CurrentDateTime + ".json")
    

        Write-Log -Message ('Report Excel File: {0}' -f $File) -Severity 'Info'
    }

    function CreateMetricsJob()
    {
        Write-Log -Message ('Checking if Metrics Job Should be Run.') -Severity 'Info'

        if (!$SkipMetrics.IsPresent) 
        {
            Write-Log -Message ('Running Metrics Jobs') -Severity 'Success'

            if($PSScriptRoot -like '*\*')
            {
                $MetricPath = Get-ChildItem -Path ($PSScriptRoot + '\Extension\Metrics.ps1') -Recurse
            }
            else
            {
                $MetricPath = Get-ChildItem -Path ($PSScriptRoot + '/Extension/Metrics.ps1') -Recurse
            }

            $metricsFilePath = ($DefaultPath + "Metrics_"+ $Global:ReportName + "_" + $CurrentDateTime + "_")
            
            $Global:AzMetrics = New-Object PSObject
            $Global:AzMetrics | Add-Member -MemberType NoteProperty -Name Metrics -Value NotSet
            $Global:AzMetrics.Metrics = & $MetricPath -Subscriptions $Global:Subscriptions -Resources $Global:Resources -Task "Processing" -File $Global:File -Metrics $null -TableStyle $null -ConcurrencyLimit $ConcurrencyLimit -FilePath $metricsFilePath
        }
    }

    function ProcessMetricsResult()
    {
        if (!$SkipMetrics.IsPresent) 
        {
            $([System.GC]::GetTotalMemory($false))
            $([System.GC]::Collect())
            $([System.GC]::GetTotalMemory($true))
        }
    }

    function GetServiceName($moduleUrl)
    {    
        if ($moduleUrl -like '*Services/Analytics*')
        {
            $directoryService = 'Analytics'
        }

        if ($moduleUrl -like '*Services/Compute*')
        {
            $directoryService = 'Compute'
        }

        if ($moduleUrl -like '*Services/Containers*')
        {
            $directoryService = 'Containers'
        }

        if ($moduleUrl -like '*Services/Data*')
        {
            $directoryService = 'Data'
        }

        if ($moduleUrl -like '*Services/Infrastructure*')
        {
            $directoryService = 'Infrastructure'
        }

        if ($moduleUrl -like '*Services/Integration*')
        {
            $directoryService = 'Integration'
        }

        if ($moduleUrl -like '*Services/Networking*')
        {
            $directoryService = 'Networking'
        }

        if ($moduleUrl -like '*Services/Storage*')
        {
            $directoryService = 'Storage'
        }

        return $directoryService
    }

    function CreateResourceJobs()
    {
        $Global:SmaResources = New-Object PSObject

        Write-Log -Message ('Starting Service Processing Jobs.') -Severity 'Info'
        

        if($PSScriptRoot -like '*\*')
        {
            $Modules = Get-ChildItem -Path ($PSScriptRoot +  '\Services\*.ps1') -Recurse
        }
        else
        {
            $Modules = Get-ChildItem -Path ($PSScriptRoot +  '/Services/*.ps1') -Recurse
        }

        $Resource = $Global:Resources | Select-Object -First $Global:Resources.Count
        #$Resource = ($Resource | ConvertTo-Json -Depth 50)

        foreach ($Module in $Modules) 
        {
            $ModName = $Module.Name.Substring(0, $Module.Name.length - ".ps1".length)
            
            Write-Log -Message ("Service Processing: {0}" -f $ModName) -Severity 'Success'

            $result = & $Module -SCPath $SCPath -Sub $Global:Subscriptions -Resources $Resource -Task "Processing" -File $Global:File -SmaResources $null -TableStyle $null -Metrics $Global:AzMetrics
            $Global:SmaResources | Add-Member -MemberType NoteProperty -Name $ModName -Value NotSet
            $Global:SmaResources.$ModName = $result

            $result = $null
            [System.GC]::Collect()
        }
    }

    function ProcessResourceResult()
    {
        Write-Log -Message ("Starting Reporting Phase.") -Severity 'Info'

        if (-not (Get-Command Export-Excel -ErrorAction SilentlyContinue)) {
            Write-Log -Message ('ImportExcel module required for Excel report. Install: Install-Module -Name ImportExcel -Scope CurrentUser') -Severity 'Error'
            return
        }

        $excelPath = $Global:File
        if ([string]::IsNullOrWhiteSpace($excelPath)) {
            $excelPath = $DefaultPath + $Global:ReportName + "_" + $CurrentDateTime + ".xlsx"
            $Global:File = $excelPath
        }

        # Ensure the Excel file exists so services and Summary can write to it (avoids missing file when no service has data)
        if (-not (Test-Path -Path $excelPath -PathType Leaf)) {
            "" | Export-Excel -Path $excelPath -WorksheetName 'Overview' -ErrorAction Stop
        }

        $Services = @()

        if($PSScriptRoot -like '*\*')
        {
            $Services = Get-ChildItem -Path ($PSScriptRoot + '\Services\*.ps1') -Recurse
        }
        else
        {
            $Services = Get-ChildItem -Path ($PSScriptRoot + '/Services/*.ps1') -Recurse
        }

        Write-Log -Message ('Services Found: ' + $Services.Count) -Severity 'Info'
        $Lops = $Services.count
        $ReportCounter = 0

        foreach ($Service in $Services) 
        {
            $c = (($ReportCounter / $Lops) * 100)
            $c = [math]::Round($c)
            
            Write-Log -Message ("Running Services: $Service") -Severity 'Info'
            try {
                $ProcessResults = & $Service.FullName -SCPath $PSScriptRoot -Sub $null -Resources $null -Task "Reporting" -File $excelPath -SmaResources $Global:SmaResources -TableStyle $Global:TableStyle -Metrics $null
            } catch {
                Write-Log -Message ("Service failed (skipping): $($Service.Name) - $_") -Severity 'Warning'
            }

            $ReportCounter++
        }

        $Global:SmaResources | Add-Member -MemberType NoteProperty -Name 'Version' -Value NotSet
        $Global:SmaResources.Version = $Global:Version

        $Global:SmaResources | ConvertTo-Json -depth 100 -compress | Out-File $Global:JsonFile
        #$Global:Resources | ConvertTo-Json -depth 100 -compress | Out-File $Global:AllResourceFile
        
        Write-Log -Message ('Resource Reporting Phase Done.') -Severity 'Info'
    }

    function GetResorceConsumption()
    {
        $DebugPreference = "SilentlyContinue"
        
        #Force the culture here...
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = "en-US"; 
        [System.Threading.Thread]::CurrentThread.CurrentCulture = "en-US";

        $reportedStartTime = (Get-Date).AddDays(-31).Date.AddHours(0).AddMinutes(0).AddSeconds(0).DateTime
        $reportedEndTime = (Get-Date).AddDays(-1).Date.AddHours(0).AddMinutes(0).AddSeconds(0).DateTime

        $Global:ConsumptionRows = [System.Collections.ArrayList]::new()

        foreach($sub in $Global:Subscriptions)
        {
            # Check if SubscriptionId is not null, not empty, and matches $sub.id
            if (![string]::IsNullOrEmpty($SubscriptionID))
            {
                if (![string]::IsNullOrEmpty($ResourceGroup))
                {
                    Write-Log -Message ("Cannot filter consumption by resource group." -f $sub.Name) -Severity 'Info'
                }

                if($SubscriptionID -ne $sub.Id)
                {
                    Write-Log -Message ("Skipping: {0}" -f $sub.Name) -Severity 'Info'
                    continue
                }
            }

            Set-AzContext -Subscription $sub.id | Out-Null
            Write-Log -Message ("Gathering Consumption for: {0}" -f $sub.Name) -Severity 'Info'

            $usageData = $null
            do 
            {    
                $params = @{
                    ReportedStartTime      = $reportedStartTime
                    ReportedEndTime        = $reportedEndTime
                    AggregationGranularity = 'Daily'
                    ShowDetails            = $true
                }
                if ($null -ne $usageData -and $usageData.PSObject.Properties['ContinuationToken'] -and $usageData.ContinuationToken)
                {
                    $params.ContinuationToken = $usageData.ContinuationToken
                }
    
                $usageData = Get-UsageAggregates @params
                $usageDataExport = $usageData.UsageAggregations.Properties | Select-Object InstanceData, MeterCategory, MeterId, MeterName, MeterRegion, MeterSubCategory, Quantity, Unit, UsageStartTime, UsageEndTime

                Write-Log -Message ("Records found: $($usageDataExport.Count)...") -Severity 'Info'

                $newUsageDataExport = [System.Collections.ArrayList]::new()

                for($item = 0; $item -lt $usageDataExport.Count; $item++) 
                {
                    $instanceInfo = ($usageDataExport[$item].InstanceData.tolower() | ConvertFrom-Json)

                    if (![string]::IsNullOrEmpty($ResourceGroup))
                    {
                        if(!$instanceInfo.'Microsoft.Resources'.resourceUri.toLower().Contains("/" + $ResourceGroup.toLower() + "/"))
                        {
                            continue;
                        }
                    }
                    
                    $usageDataExport[$item] | Add-Member -MemberType NoteProperty -Name ResourceId -Value NotSet
                    $usageDataExport[$item] | Add-Member -MemberType NoteProperty -Name ResourceLocation -Value NotSet

                    $usageDataExport[$item] | Add-Member -MemberType NoteProperty -Name ConsumptionMeter -Value NotSet
                    $usageDataExport[$item] | Add-Member -MemberType NoteProperty -Name ReservationId -Value NotSet
                    $usageDataExport[$item] | Add-Member -MemberType NoteProperty -Name ReservationOrderId -Value NotSet

        
                    $usageDataExport[$item].ResourceId = $instanceInfo.'Microsoft.Resources'.resourceUri
                    $usageDataExport[$item].ResourceLocation = $instanceInfo.'Microsoft.Resources'.location
                    $usageDataExport[$item].ConsumptionMeter = $instanceInfo.'Microsoft.Resources'.additionalInfo.ConsumptionMeter
                    $usageDataExport[$item].ReservationId = $instanceInfo.'Microsoft.Resources'.additionalInfo.ReservationId
                    $usageDataExport[$item].ReservationOrderId = $instanceInfo.'Microsoft.Resources'.additionalInfo.ReservationOrderId
                    

                    $instanceObject = [PSCustomObject]@{}

                    $additionalInfoInstance = [PSCustomObject]@{
                        ResourceUri = $instanceInfo.'Microsoft.Resources'.resourceUri
                        Location = $instanceInfo.'Microsoft.Resources'.location
                        additionalInfo = [PSCustomObject]@{
                            ConsumptionMeter = if ($null -eq $instanceInfo.'Microsoft.Resources'.additionalInfo.ConsumptionMeter) { "" } else { $instanceInfo.'Microsoft.Resources'.additionalInfo.ConsumptionMeter }
                            vCores = 0
                            VCPUs = 0
                            ServiceType = ""
                            ResourceCategory = ""
                        }
                    }
                    
                    $instanceObject | Add-Member -MemberType NoteProperty -Name "Microsoft.Resources" -Value $additionalInfoInstance

                    $usageDataExport[$item].InstanceData = $instanceObject | ConvertTo-Json -Compress

                    $newUsageDataExport.Add($usageDataExport[$item]) | Out-Null
                }

                $batchRows = $newUsageDataExport | Select-Object InstanceData, MeterCategory, MeterId, MeterName, MeterRegion, MeterSubCategory, Quantity, Unit, UsageStartTime, UsageEndTime, ResourceId, ResourceLocation, ConsumptionMeter, ReservationId, ReservationOrderId
                foreach ($r in $batchRows) { $Global:ConsumptionRows.Add($r) | Out-Null }

                $batchRows | Export-Csv $Global:ConsumptionFileCsv -Encoding utf8 -Append -NoTypeInformation
                
            } while ($null -ne $usageData -and 'ContinuationToken' -in $usageData.psobject.properties.name -and $usageData.ContinuationToken)
        }

        if ($Global:ConsumptionRows.Count -gt 0 -and (Test-Path -Path $Global:File -PathType Leaf)) {
            Write-Log -Message ('Writing Consumption to Excel: {0} rows' -f $Global:ConsumptionRows.Count) -Severity 'Info'
            $Global:ConsumptionRows | Export-Excel -Path $Global:File -WorksheetName 'Consumption' -AutoSize -MaxAutoSizeRows 500 -TableStyle $Global:TableStyle
        }

        $DebugPreference = "Continue"
    }

    InitializeInventoryProcessing
    CreateMetricsJob
    CreateResourceJobs   
    ProcessMetricsResult
    ProcessResourceResult

    if(!$SkipConsumption.IsPresent)
    {
       GetResorceConsumption
       #ProcessResourceConsumption
    }
}

function FinalizeOutputs
{
    function ProcessSummary()
    {
        Write-Log -Message ('Creating Summary Report') -Severity 'Info'
        Write-Log -Message ('Starting Summary Report Processing Job.') -Severity 'Info'

        if($PSScriptRoot -like '*\*')
        {
            $SummaryPath = Get-ChildItem -Path ($PSScriptRoot + '\Extension\Summary.ps1') -Recurse
        }
        else
        {
            $SummaryPath = Get-ChildItem -Path ($PSScriptRoot + '/Extension/Summary.ps1') -Recurse
        }

        $ChartsRun = & $SummaryPath -File $Global:File -TableStyle $TableStyle -PlatOS $PlatformOS -Subscriptions $Global:Subscriptions -Resources $Global:Resources -ExtractionRunTime $Runtime -ReportingRunTime $ReportingRunTime -RunLite $false -Version $Global:Version
    }

    ProcessSummary
}

$Global:PowerShellTranscriptFile = ($DefaultPath + "Transcript_Log_"+ $Global:ReportName + "_" + $CurrentDateTime + ".txt")
Start-Transcript -Path $Global:PowerShellTranscriptFile -UseMinimalHeader

# Setup and Inventory Gathering
$Global:Runtime = Measure-Command -Expression {
    Variables
    RunInventorySetup
}

# Execution and processing of inventory
$Global:ReportingRunTime = Measure-Command -Expression {
    ExecuteInventoryProcessing
}

Stop-Transcript

# Prepare the summary and outputs
FinalizeOutputs

Write-Log -Message ("Compressing Resources Output: {0}" -f $Global:ZipOutputFile) -Severity 'Info'

if($EnableLogs.IsPresent)
{
    $Global:Logging | ConvertTo-Json -depth 5 -compress | Out-File $Global:LogFile
} 

if($SkipMetrics.IsPresent)
{
    "Metrics Not Gathered" | ConvertTo-Json -depth 5 -compress | Out-File $Global:MetricsJsonFile 
}

$consumptionCreated = Test-Path -Path $Global:ConsumptionFileCsv

if($SkipConsumption.IsPresent -or !$consumptionCreated)
{
    Out-File $Global:ConsumptionFileCsv
}

# Build list of existing files only (Compress-Archive fails if any path does not exist)
$pathsToCompress = @()
if (Test-Path -Path $Global:File -PathType Leaf) { $pathsToCompress += $Global:File }
if (Test-Path -Path $Global:ConsumptionFileCsv -PathType Leaf) { $pathsToCompress += $Global:ConsumptionFileCsv }
if (Test-Path -Path $Global:PowerShellTranscriptFile -PathType Leaf) { $pathsToCompress += $Global:PowerShellTranscriptFile }
$jsonFiles = Get-ChildItem -Path ($DefaultPath + "*.json") -ErrorAction SilentlyContinue
if ($jsonFiles) { $pathsToCompress += $jsonFiles.FullName }

if ($pathsToCompress.Count -gt 0)
{
    try
    {
        Compress-Archive -Path $pathsToCompress -CompressionLevel Fastest -DestinationPath $Global:ZipOutputFile
    }
    catch
    {
        $_ | Format-List -Force
        Write-Error ("Error Compressing Output File: {0}." -f $Global:ZipOutputFile)
        Write-Error ("Please zip the output files manually.")
    }
}
else
{
    Write-Log -Message ("No output files to compress; zip was not created.") -Severity 'Warning'
}

Write-Log -Message ("Execution Time: {0}" -f $Runtime) -Severity 'Success'
Write-Log -Message ("Reporting Time: {0}" -f $ReportingRunTime) -Severity 'Success'
Write-Log -Message ("Reporting Data File: {0}" -f $Global:ZipOutputFile) -Severity 'Success'
