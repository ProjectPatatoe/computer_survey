<#
.SYNOPSIS
	Get commonly useful computer info in a domain OU/list and then export to a Tab seperated txt/tsv.
	Useful for inventory.
.DESCRIPTION
	Takes a list of hostnames and/or a domain OU and queries the computer for detailed Hardware and
	OS information. Then exports to a Tab seperated value txt/tsv. Useful for taking inventory.
	Can also check for DNS mismatch issues (WIP). 
.PARAMETER ComputerName
	A string[] of computer names to test against. Ex: "hostname1","hostname2"
.PARAMETER OrgUnit
	A string[] of domain organization units's Distinguished Name to test against.
	Ex: "OU=some-Unit,DC=some-domain","OU=subOrg,OU=some-Other-Unit,DC=some-domain"
.PARAMETER ExportList
	A string path to export just a list of computers to test against (txt)
.PARAMETER ExportTab
	A string path to export the tab-seperated results of the full test/survey (txt/tsv)
.PARAMETER ForceReturn
	When exporting as list/tab, it doesn't return the result list. This will force it.
.PARAMETER Debug
	Extra debugging output
.PARAMETER DnsChecking
	(WIP, doesn't test other suffixes) Tests if domain suffix and multucast dns match.
#>
Param(
    [string[]]$ComputerName,
	[string[]]$OrgUnit,
    [string]$ExportList,
	[string]$ExportTab,
	[switch]$ForceReturn,
	[switch]$Debug,
	[switch]$DnsChecking
)
if($PSBoundParameters.Values.Count -eq 0) {
    Get-Help $MyInvocation.MyCommand.Definition -Detailed
    return
}

Import-Module QuserObject #nice clean wrapper for using quser / query user

#FIXME reorganize processing and declarations

##### Get computer list #####
[pscustomobject[]]$computer_list = @()
if ($Debug) {
	"DEBUG Mode"
	#custom computer list for testing
	$computer_list += @( 	[pscustomobject]@{Name='debug-mode'},
							[pscustomobject]@{Name='localhost'},
							[pscustomobject]@{Name='potato'})
	$DebugPreference = 'Continue'
	$VerbosePreference = 'Continue'
}
if ($OrgUnit)
{
	Write-Debug ("Adding OU:{0}" -f $OU)
	foreach ($item in $OrgUnit) {
		"Adding OU:{0}" -f $item
		$computer_list += Get-ADComputer -Filter * -SearchBase $item  -Properties Name,DnsHostName,IPv4Address,Description
	}
}
if ($ComputerName)
{
	Write-Debug ("Adding ComputerName:{0}" -f $ComputerName)
	foreach ($item in $ComputerName) {
		"Item:{0}" -f $item
		$computer_list += [pscustomobject]@{Name=$item}
	}
}
"Number of Devices:{0}" -f $computer_list.Length

#TODO other options than dcom
$cimSessionOption = new-cimsessionoption -protocol dcom #because less things need to happen for dcom
##### define class #####
class Computer_class {
	[string]  $Name
	[string]  $Description
	[string]  $DNS_domain
	[string]  $DNS_local
	[bool]    $DNS_match
	[string]  $DNSHostName
	[string]  $SMBIOSBIOSVersion
	[string]  $SerialNumber
	[string]  $SMBIOSAssetTag
	[string]  $Model
	[int]     $RAM_SlotsTotal
	[int]     $RAM_MaxCapacityGB
	[string]  $RAM_1_Slot
	[string]  $RAM_1_Manufacturer
	[string]  $RAM_1_Model
	[string]  $RAM_1_SizeGB
	[int]     $RAM_1_ClockSpeed
	[string]  $RAM_2_Slot
	[string]  $RAM_2_Manufacturer
	[string]  $RAM_2_Model
	[string]  $RAM_2_SizeGB
	[int]     $RAM_2_ClockSpeed
	[string]  $RAM_3_Slot
	[string]  $RAM_3_Manufacturer
	[string]  $RAM_3_Model
	[string]  $RAM_3_SizeGB
	[int]     $RAM_3_ClockSpeed
	[string]  $RAM_4_Slot
	[string]  $RAM_4_Manufacturer
	[string]  $RAM_4_Model
	[string]  $RAM_4_SizeGB
	[int]     $RAM_4_ClockSpeed
	[string]  $NIC_Name
	[string]  $NIC_MacAddress
	[bool]    $NIC_More
	[string]  $CPU_Name
	[string]  $OS_Version
	[string]  $OS_Caption
	[DateTime]$OS_LastBootUpTime
	[string]  $DSK_FriendlyName
	[string]  $DSK_MediaType
	[string]  $DSK_BusType
	[string]  $DSK_FirmwareVersion
	[string]  $DSK_SerialNumber
	[int]     $DSK_SizeGB
	[bool]    $DSK_More
	[string]  $DRV_DeviceID
	[int]     $DRV_FreeSpaceGB
	[int]     $DRV_SizeGB
	[single]  $DRV_UsedPct
	[bool]    $DRV_More
	[string]  $TPM_ManufacturerIdTxt
	[string]  $TPM_ManufacturerVersion
	[string]  $TPM_SpecVersion
	[string]  $User
}
[Computer_class[]] $computer_results=@()
##### Get computer details #####
#$DNSsuffix = (Get-DnsClientGlobalSetting).SuffixSearchList[0]
$DNSsuffix = (Get-DnsClientGlobalSetting).SuffixSearchList[-1] #FIXME for a problem with this network specifically ):
Write-Debug ("DNSsuffix:{0}" -f $DNSsuffix)
foreach($computer in $computer_list)
{
	$cNew = [Computer_class]::new()
	Write-Debug "============================================================"
	Write-Host $computer.Name
	$cNew.Name=$computer.Name
	$cNew.Description=$computer.Description
	$cUsedAddress = ''
	
	##### DNS matching
	if ($DnsChecking) {
		Write-Debug "DNS Checking"
		#TODO search through array of suffixs
		$cNew.DNS_domain = (resolve-dnsname -Name ("{0}.{1}" -f $computer.Name,$DNSsuffix) -QuickTimeout -Type A -ErrorAction SilentlyContinue).IP4Address
		$cNew.DNS_local = (resolve-dnsname -Name ("{0}.local"-f $computer.Name) -QuickTimeout -Type A -ErrorAction SilentlyContinue).IP4Address
		Write-Debug ("DNS_DOMAIN:{0}" -f $cNew.DNS_domain)
		Write-Debug ("DNS_LOCAL:{0}" -f $cNew.DNS_local)
		if ($cNew.DNS_domain -eq $cNew.DNS_local)
		{
			Write-Debug "DNS Match!"
			$cNew.DNS_match = $true
		}
		else
		{
			Write-Debug "DNS Mismatch!"
			$cNew.DNS_match = $false
			#$cNew.ErrorFree=$false
		}
		
		##### determine which cimsession #####
		if ($cNew.DNS_match -and ($cNew.DNS_domain -ne ''))
		{
			Write-Debug "Matched"
			$cimSession = new-cimsession -sessionoption $cimSessionOption -computername $computer.Name
			$cUsedAddress = $computer.Name
		}
		else
		{
			if ($cNew.DNS_domain -ne '')
			{
				Write-Host "Trying domain..."
				$cimSession = new-cimsession -sessionoption $cimSessionOption -computername $cNew.DNS_domain
				if ($cimSession)
				{
					Write-Debug "domain session active"
					$computersystem = Get-CimInstance win32_computersystem -cimsession $cimSession | Select-Object DNSHostName
					if ($computersystem.DNSHostName -ne $cNew.Name)
					{
						Write-Debug "Wrong computer!"
						Remove-CimSession $cimSession
						Clear-Variable cimSession
					}
					else
					{ $cUsedAddress = $cNew.DNS_domain }
				}
			}
			if (($cNew.DNS_local -ne '') -and (!$cimSession))
			{
				Write-Host "Trying local..."
				$cimSession = new-cimsession -sessionoption $cimSessionOption -computername $cNew.DNS_local
				if ($cimSession)
				{
					Write-Debug "local session active"
					$computersystem = Get-CimInstance win32_computersystem -cimsession $cimSession | Select-Object DNSHostName
					if ($computersystem.DNSHostName -ne $cNew.Name)
					{
						Write-Debug "Wrong computer!"
						Remove-CimSession $cimSession
						Clear-Variable cimSession
					}
					else
					{ $cUsedAddress = $cNew.DNS_local }
				}
			}
		}
	} #if (DnsChecking)
	else {
		$cimSession = new-cimsession -sessionoption $cimSessionOption -computername $computer.Name
		$cUsedAddress = $computer.Name
	}
	if ($cimSession)
	{
		##### BIOS
		#tested on dell
		$bios = Get-CimInstance win32_bios -cimsession $cimSession | Select-Object SMBIOSBIOSVersion,SerialNumber
		Write-Debug $bios | format-list
		$cNew.SMBIOSBIOSVersion = $bios.SMBIOSBIOSVersion
		$cNew.SerialNumber = $bios.SerialNumber
		##### Chassis
		#tested on dell
		$chassis = Get-CimInstance cim_chassis -cimsession $cimSession | Select-Object SMBIOSAssetTag
		Write-Debug $chassis | format-list
		$cNew.SMBIOSAssetTag = $chassis.SMBIOSAssetTag
		##### Computersystem
		$computersystem = Get-CimInstance win32_computersystem -cimsession $cimSession | Select-Object DNSHostName,Model
		Write-Debug $computersystem | format-list
		$cNew.DNSHostName = $computersystem.DNSHostName
		$cNew.Model = $computersystem.Model
		##### Physical memory array
		$physicalMemoryArray = Get-CimInstance win32_physicalmemoryarray -cimsession $cimSession |
				Select-Object -Property @{Name="SlotsTotal";Expression={$_.MemoryDevices}},
										@{Name="MaxCapacityGB";Expression={$_.MaxCapacity/1024/1024}}
										
		$physicalMemoryArray | Out-String -Stream | ForEach-Object TrimEnd | Write-Debug
		$cNew.RAM_SlotsTotal = $physicalMemoryArray.SlotsTotal
		$cNew.RAM_MaxCapacityGB = $physicalMemoryArray.MaxCapacityGB
		##### physicalmemory
		$physicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -cimsession $cimSession | 
			Select-Object -Property @{Name="RAMSlot";Expression={$_.DeviceLocator}},
									Manufacturer,
									@{Name="Model";Expression={$_.PartNumber}},
									@{Name="SizeGB";Expression={[math]::round(($_.Capacity/1gb))}},
									@{Name="ClockSpeed";Expression={$_.ConfiguredClockSpeed}}
		$physicalMemory | Out-String -Stream | ForEach-Object TrimEnd | Write-Debug
		$cNew.RAM_1_Slot 			= $physicalMemory[0].RamSlot
		$cNew.RAM_1_Manufacturer 	= $physicalMemory[0].Manufacturer
		$cNew.RAM_1_Model 			= $physicalMemory[0].Model
		$cNew.RAM_1_SizeGB 			= $physicalMemory[0].SizeGB
		$cNew.RAM_1_ClockSpeed 		= $physicalMemory[0].ClockSpeed
		if ($physicalMemory.length -ge 2)
		{
			$cNew.RAM_2_Slot 			= $physicalMemory[1].RamSlot
			$cNew.RAM_2_Manufacturer 	= $physicalMemory[1].Manufacturer
			$cNew.RAM_2_Model 			= $physicalMemory[1].Model
			$cNew.RAM_2_SizeGB 			= $physicalMemory[1].SizeGB
			$cNew.RAM_2_ClockSpeed 		= $physicalMemory[1].ClockSpeed
		}
		if ($physicalMemory.length -ge 3)
		{
			$cNew.RAM_3_Slot 			= $physicalMemory[2].RamSlot
			$cNew.RAM_3_Manufacturer 	= $physicalMemory[2].Manufacturer
			$cNew.RAM_3_Model 			= $physicalMemory[2].Model
			$cNew.RAM_3_SizeGB 			= $physicalMemory[2].SizeGB
			$cNew.RAM_3_ClockSpeed 		= $physicalMemory[2].ClockSpeed
		}
		if ($physicalMemory.length -ge 4)
		{
			$cNew.RAM_4_Slot 			= $physicalMemory[3].RamSlot
			$cNew.RAM_4_Manufacturer 	= $physicalMemory[3].Manufacturer
			$cNew.RAM_4_Model 			= $physicalMemory[3].Model
			$cNew.RAM_4_SizeGB 			= $physicalMemory[3].SizeGB
			$cNew.RAM_4_ClockSpeed 		= $physicalMemory[3].ClockSpeed
		}
		##### processor
		$processor = Get-CimInstance win32_Processor -cimsession $cimSession | Select-Object -Property Name
		$processor | Out-String -Stream | ForEach-Object TrimEnd | Write-Debug
		$cNew.CPU_NAME = $processor.Name
		##### nics network
		$nics = Get-CimInstance cim_networkadapter -cimsession $cimSession | Where-object {$_.PhysicalAdapter -eq $true} | Select-Object -Property Index,Name,MacAddress
		$nics | Out-String -Stream | ForEach-Object TrimEnd | Write-Debug
		$cNew.NIC_Name = $nics[0].Name
		$cNew.NIC_MacAddress = $nics[0].MacAddress
		$cNew.NIC_More = $(If ($nics.length -gt 1) { $true } else { $false })
		##### operatingSystem
		$operatingSystem = Get-CimInstance cim_OperatingSystem | Select-Object Version,Caption,LastBootUpTime
		$operatingSystem | Out-String -Stream | ForEach-Object TrimEnd | Write-Debug
		$cNew.OS_Version = $operatingSystem.Version
		$cNew.OS_Caption = $operatingSystem.Caption
		$cNew.OS_LastBootUpTime = $operatingSystem.LastBootUpTime
		
		##### physicalDisk
		$physicalDisk = Get-CimInstance msft_physicaldisk -Namespace root\Microsoft\Windows\Storage -cimsession $cimsession | Select-Object	FriendlyName,
										MediaType,
										BusType,
										FirmwareVersion,
										SerialNumber,
										@{Name="SizeGB";Expression={[math]::round(($_.Size/1gb))}}
		$physicalDisk | Out-String -Stream | ForEach-Object TrimEnd | Write-Debug
		$cNew.DSK_FriendlyName = $physicalDisk[0].FriendlyName
		Switch ($physicalDisk[0].MediaType)
		{
			0 {$cNew.DSK_MediaType="Unspecified"}
			3 {$cNew.DSK_MediaType="HDD"}
			4 {$cNew.DSK_MediaType="SSD"}
			5 {$cNew.DSK_MediaType="SCM"}
			default {$cNew.DSK_MediaType="Unknown"}
		}
		Switch ($physicalDisk[0].BusType)
		{
			1 {$cNew.DSK_BusType="SCSI"}
			2 {$cNew.DSK_BusType="ATAPI"}
			3 {$cNew.DSK_BusType="ATA"}
			4 {$cNew.DSK_BusType="1394"}
			5 {$cNew.DSK_BusType="SSA"}
			6 {$cNew.DSK_BusType="FibreChannel"}
			7 {$cNew.DSK_BusType="USB"}
			8 {$cNew.DSK_BusType="RAID"}
			9 {$cNew.DSK_BusType="iSCSI"}
			10 {$cNew.DSK_BusType="SAS"}
			11 {$cNew.DSK_BusType="SATA"}
			12 {$cNew.DSK_BusType="SD"}
			13 {$cNew.DSK_BusType="MMC"}
			#14 {$cNew.DSK_BusType="MAX"}
			15 {$cNew.DSK_BusType="FileBackedVirtual"}
			16 {$cNew.DSK_BusType="StorageSpaces"}
			17 {$cNew.DSK_BusType="NVMe"}
			#18 {$cNew.DSK_BusType=""}
			default {$cNew.DSK_BusType="Unknown"}
		}
		$cNew.DSK_FirmwareVersion = $physicalDisk[0].FirmwareVersion
		$cNew.DSK_SerialNumber = $physicalDisk[0].SerialNumber
		$cNew.DSK_SizeGB = $physicalDisk[0].SizeGB
		$cNew.DSK_More = $(If ($physicalDisk.length -gt 1) { $true } else { $false })
		
		##### logicaldisk
		$logicalDisk = Get-CimInstance cim_LogicalDisk -cimsession $cimsession | 
		where-object -property DriveType -eq 3 | 
		select-object -Property	DeviceID,
								@{Name="FreeSpaceGB";Expression={[math]::round(($_.FreeSpace/1gb))}},
								@{Name="SizeGB";Expression={[math]::round(($_.Size/1gb))}},
								@{Name="UsedPct";Expression={[math]::round((($_.Size-$_.Freespace)/$_.Size*100),1)}}
		$logicalDisk | Out-String -Stream | ForEach-Object TrimEnd | Write-Debug
		$cNew.DRV_DeviceID = $logicalDisk[0].DeviceID
		$cNew.DRV_FreeSpaceGB = $logicalDisk[0].FreeSpaceGB
		$cNew.DRV_SizeGB = $logicalDisk[0].SizeGB
		$cNew.DRV_UsedPct = $logicalDisk[0].UsedPct
		$cNew.DRV_More = $(If ($logicalDisk.length -gt 1) { $true } else { $false })
		
		##### tpm
		$tpm = get-ciminstance win32_tpm -Namespace root\cimv2\security\MicrosoftTpm -cimsession $cimsession |
			select-object -property ManufacturerIdTxt,
									ManufacturerVersion,
									SpecVersion
		
		$tpm | Out-String -Stream | ForEach-Object TrimEnd | Write-Debug
		$cNew.TPM_ManufacturerIdTxt = $tpm.ManufacturerIdTxt
		$cNew.TPM_ManufacturerVersion = $tpm.ManufacturerVersion
		$cNew.TPM_SpecVersion = $tpm.SpecVersion

		Remove-CimSession -Id $cimSession.Id
		Clear-Variable cimSession

		if (Get-Module QuserObject)
		{
			$cNew.User = (get-QUser -Server $cUsedAddress).UserName
		}
	} #if cimsession
	else
	{
		Write-Host ("{0} Could not connect" -f $computer.Name) -ForegroundColor Red
		#$cNew.ErrorFree=$false
	}
	$computer_results += ($cNew)
}
Write-Host $computer_results | Select-Object Name,SerialNumber,OS_LastBootUpTime,User | Format-Table
if ($ExportList)
{
	$computer_list | Out-File -FilePath $ExportList
}
if ($ExportTab)
{
	"Exporting to txt...Tab delimited. open in excel"
	$computer_results | Export-CSV -Delimiter '	' -Path $ExportTab
}
if ($ForceReturn -or (!$ExportList -and !$ExportTag))
{
	return $computer_results
}
"done"