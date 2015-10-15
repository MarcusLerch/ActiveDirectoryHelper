<#
=============================================================================
THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

This sample is not supported under any standard support program or
service. The code sample is provided AS IS without warranty of any kind.
lmxlabs further disclaims all implied warranties including, without
limitation, any implied warranties of merchantability or of fitness for a
particular purpose. The entire risk arising out of the use or performance of
the sample and documentation remains with you. In no event shall lmxlabs, 
its authors, or anyone else involved in the creation, production, or delivery 
of the script be liable for any damages whatsoever (including, without 
limitation, damages for loss of business profits, business interruption, loss
of business information, or other pecuniary loss) arising out of  the use of
or inability to use the sample or documentation, even if lmxlabs has been 
advised of the possibility of such damages.
=============================================================================
#>

function Test-DNSRegistration {
    [CmdletBinding(DefaultParametersetName="LocalCheck")] 
	param(
        [Parameter(ParametersetName="ProvidedList", Mandatory=$true)]
        [Parameter(ParametersetName="RemoteCheck", Mandatory=$true, ValueFromPipeline=$true)]
        [System.String[]]
        $Server,
		[Parameter(ParametersetName="LocalCheck")]
		[Parameter(ParametersetName="RemoteCheck")]
		[Parameter(ParametersetName="ProvidedList")]
        [System.String]
        $DNSServerAdress,
		[Parameter(ParametersetName="ProvidedList", Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.String[]]
		$DNSRecordList
)
Begin {    
    switch ($PSCmdlet.ParameterSetName){
        "LocalCheck" { 
            if (Test-Path $env:SystemRoot\System32\config\netlogon.dns -PathType Leaf){
                $DNSRecordList = Get-Content $env:SystemRoot\System32\config\netlogon.dns
                $Server = $env:COMPUTERNAME
            }
            else{
                Write-Output ("Could not read {0}`nPlease verify the existence of the netlogon.dns File.`nIs the local machine really a domain controller?" -f "$env:SystemRoot\System32\config\netlogon.dns" )
            }
        }
        "RemoteCheck" {
            #$DNSRecordList = @()
            foreach ($SingleServer in $Server){
                $NetLogonDNSPath = '\\{0}\admin$\\System32\config\netlogon.dns' -f $SingleServer
                if (Test-Path $NetLogonDNSPath -PathType Leaf){
                    $DNSRecordList += Get-Content $NetLogonDNSPath
                }
                else{
                    Write-Output ("Could not read {0}`nPlease verify the existence of the netlogon.dns File.`nIs the target machine really a domain controller?" -f $NetLogonDNSPath)
                }
            }
        }
    }
    if($DNSServerAdress -eq ""){
        $DNSServerAdress = ((Get-DnsClientServerAddress -AddressFamily IPv4) | Where-Object {$_.ServerAddresses})[0].ServerAddresses[0]
    }
    $ServiceRecordList = @()
}
Process {
	foreach ($DNSEntry in $DNSRecordList){
		$Entry = $DNSEntry -split " "
		$DNSName = $Entry[0]
        $DNSTTL = $Entry[1]
		$DNSType = $Entry[3]
        if ($DNSType -eq "SRV"){
            $SRVPriority = $Entry[4]
            $SRVWeight = $Entry[5]
            $SRVPort = $Entry[6]
        }
        $ServerInQuestion = ($Entry[-1]).TrimEnd(".")
        $ServiceRecord = New-Object System.Object | Select-Object SourceServer,DNSRecord,DNSRecordType,IsRegistered,IsCorrect,DNSServer
        $ServiceRecord.SourceServer = $ServerInQuestion
        $ServiceRecord.DNSRecord = $DNSName
        $ServiceRecord.DNSRecordType = $DNSType
        $ServiceRecord.IsRegistered = $false
        $ServiceRecord.IsCorrect = $false
        $ServiceRecord.DNSServer = $DNSServerAdress
        $nslResults = Resolve-DnsName -Name $DNSName -Type $DNSType -DnsOnly -Server $DNSServerAdress -ErrorAction SilentlyContinue
		switch ($DNSType) {
			
            "SRV" {
                foreach ($nslResult in $nslResults){
                    if ($nslResult.NameTarget -eq $ServerInQuestion){
                        $ServiceRecord.IsRegistered = $true
                        if ($nslResult.TTL -eq $DNSTTL -and 
                            $nslResult.Priority -eq $SRVPriority -and 
                            $nslResult.Weight -eq $SRVWeight -and 
                            $nslResult.Port -eq $SRVPort){
                            $ServiceRecord.IsCorrect = $true
                        }
                        break
                    }
              }
				
			}

			"A" {
				foreach ($nslResult in $nslResults){
                    if ($nslResult.IP4Address -eq $ServerInQuestion){
                        $ServiceRecord.IsRegistered = $true
                        if ($nslResult.TTL -eq $DNSTTL){
                            $ServiceRecord.IsCorrect = $true
                        }
                        break
                    }
              }
			}

			"CNAME" {
				foreach ($nslResult in $nslResults){
                    if ($nslResult.NameHost -eq $ServerInQuestion){
                        $ServiceRecord.IsRegistered = $true
                        if ($nslResult.TTL -eq $DNSTTL){
                            $ServiceRecord.IsCorrect = $true
                        }
                        break
                    }
              }
			}

			Default {
				break
			}
		}
        $ServiceRecordList += $ServiceRecord
	}
}
End {
    $ServiceRecordList | Sort-Object DNSRecordType, DNSRecord
}
}

function Test-TCPPort {
    param ( 
        [ValidateNotNullOrEmpty()]
        [string] $EndPoint = $(throw "Please specify an EndPoint (Host or IP Address)"),
        [string] $Port = $(throw "Please specify a Port"),
        [int] $TimeOut = 1000
   )
       
    Try{
        $IP = [System.Net.Dns]::GetHostAddresses($EndPoint) # | Where-Object {$_.AddressFamily -eq 'InterNetwork'}
        $Address = [System.Net.IPAddress]::Parse($IP)
        $Socket = New-Object System.Net.Sockets.TCPClient
        $Connect = $Socket.BeginConnect($Address,$Port,$null,$null)
    }
    catch{
        return "Host not reachable"
    }
    if ( $Connect.IsCompleted )
    {
            $Wait = $Connect.AsyncWaitHandle.WaitOne($TimeOut,$false)                 
            if(!$Wait) 
            {
                $Socket.Close() 
                return $false 
            } 
            else
            {
                $Socket.EndConnect($Connect)
                $Socket.Close()
                return $true
            }
    }
    else
    {
            return $false
    }
}

function Connect-ADDomain {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][String]$TargetDomain,
        [String]$TargetServer,
        [String]$DriveName,
        [String]$TargetRoot = "",
        [pscredential]$TargetCred

    )
    Import-Module ActiveDirectory
    if (!$DriveName) {
        Write-Verbose "DriveName not specified trying to get NetBIOS Name for $TargetDomain"
        $DriveName = ($TargetDomain -split "\.")[0]
        Write-Verbose "DriveName set to --> $DriveName <--"
    }
        if (!$TargetServer){ $TargetServer = (Get-ADDomainController -DomainName $TargetDomain -Discover).Hostname[0].tostring()}

    if (!$TargetCred){
        New-PSDrive -Name $DriveName -PSProvider ActiveDirectory -Root "" -Server $TargetServer -Scope Global
    }
    else {
        New-PSDrive -Name $DriveName -PSProvider ActiveDirectory -Root "" -Server $TargetServer -Credential $TargetCred -Scope Global
    }
}

function Get-TokenGroups{
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )
    Try{
        $user = Get-ADUser -Identity $Username
    }
    catch{
        Write-Output ("No such userobject found")
    }
    if($user){
        $ht_Output = @{}
        $Tokengrous = (Get-ADObject -Identity $user -Properties TokenGroups).Tokengroups
        Write-Verbose ("Found {0} tokengroups" -f $Tokengrous.count)
        foreach ($group in $Tokengrous){
            Try{
                $groupObject = Get-ADGroup -Identity $group
                $ht_Output.Add($groupObject.SID,$groupObject.Name)
                Write-Verbose ("Evaluated SID {0} to {1}" -f $groupObject.Name,$groupObject.SID)
            }
            catch{
                Write-Verbose ("Could not evaluate SID {0}" -f $group)
                $ht_Output.Add($group,"no object in domain")
            }
        }
        $ht_Output
    }
} 