

# Specify OU of AD

$oupath = 'DC=zuhause,DC=local'



 

# Path and Name for the Results CSV-File 

$csvpath = 'C:\Temp'
$csvname = 'Old-Protocols_table.csv'



 

# Creating the table

$table = ''
$table = New-Object system.Data.DataTable "Protocols-Table"
$col1 = New-Object system.Data.DataColumn Name,([string])
$col2 = New-Object system.Data.DataColumn Pingable,([string])
$col3 = New-Object system.Data.DataColumn Operating_System,([string])
$col4 = New-Object system.Data.DataColumn LastLogon,([string])
$col5 = New-Object system.Data.DataColumn SMB_SigningRequiredIncoming,([string])
$col6 = New-Object system.Data.DataColumn SMB_SigningRequiredOutgoing,([string])
$col7 = New-Object system.Data.DataColumn SMBv1_Incoming_Active,([string])
$col8 = New-Object system.Data.DataColumn SMBv1_Feature,([string])
$col9 = New-Object system.Data.DataColumn LLMNR,([string])
$col10 = New-Object system.Data.DataColumn LDAP_Signing,([string])
$col11 = New-Object system.Data.DataColumn NetBIOS,([string])
$col12 = New-Object system.Data.DataColumn NTLM_Level,([string])
$col13 = New-Object system.Data.DataColumn Restrict_NTLM_Incoming,([string])
$col14 = New-Object system.Data.DataColumn Restrict_NTLM_Outgoing,([string])


$table.columns.add($col1)
$table.columns.add($col2)
$table.columns.add($col3)
$table.columns.add($col4)
$table.columns.add($col5)
$table.columns.add($col6)
$table.columns.add($col7)
$table.columns.add($col8)
$table.columns.add($col9)
$table.columns.add($col10)
$table.columns.add($col11)
$table.columns.add($col12)
$table.columns.add($col13)
$table.columns.add($col14)




# Read the AD Computers

$ou = Get-ADComputer -Filter * -SearchBase $oupath


# Test existance of the Path for the Results CSV
if (Test-Path -Path  $csvpath) {
  
  


# Get Computer names
$computers = $OU.name

# Get the amount of Computer objects in the OU
$anzahl = $computers.Count

# Set Counter for progress indicator to 0
$zahl = 0


# For testing purposes, here one computer can be specified and only that one will be queried
# $computers = 'win-2022-01'

 

#  begin the queries
foreach ($c in $computers) {

  

  # Progress counter

  $zahl = $zahl + 1
  "Computer $zahl von $anzahl : $c" | Write-Host -ForegroundColor Yellow

  # add new row in the results table

  $row = $table.NewRow()
  $row.Name = $c

  # query the Operating System of the Computer from AD and put it to the table 
  $OS_AD = Get-adcomputer $C -properties OperatingSystem,LastLogonDate
  $row.Operating_System = $OS_AD.OperatingSystem
  $row.LastLogon = $OS_AD.LastLogonDate

 
  # if computer responds to ping

  if (Test-Connection $c -Count 1 -Quiet) {
    "$c is pingable." | Write-Host -ForegroundColor Green
      $row.Pingable = "Yes"

    # only if the OS is Windows go on
    if ($OS_AD.OperatingSystem -like "Windows*") {
    
     
      # read the registry for SMB parameters 1
      $SMBPara, $SMBParaC, $LLMNR_On, $smb, $ldapsign, $NetBios, $NTLM_Level, $RestrNTLMTraffic = Invoke-Command -computername $c -ErrorAction SilentlyContinue {
        Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "*"
        Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name "*"
        Get-ItemProperty -Path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
        Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | select State
        Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ldap -Name "*"
        Get-WmiObject win32_networkadapterconfiguration -filter 'IPEnabled=true' | select Description, TcpipNetbiosOptions
        Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "lmcompatibilitylevel"
        Get-ItemProperty -Path "HKLM:System\CurrentControlSet\Control\Lsa\MSV1_0"

        }

      # make the parameters readable
        if ($SMBPara.SMB1 -eq "0") {
          $row.SMBv1_Incoming_Active = "Disabled"
          } elseif ($SMBPara.SMB1 -eq "1") {
            $row.SMBv1_Incoming_Active = "Enabled"
            } elseif (-not $SMBPara.SMB1) {
                $row.SMBv1_Incoming_Active = "See SMBv1_Feature"
              } else {
                  $row.SMBv1_Incoming_Active = $SMBPara.SMB1
        }

      # make the parameters readable
        if ($SMBPara.RequireSecuritySignature -eq 0) {
          $row.SMB_SigningRequiredIncoming = "Disabled"
          } elseif ($SMBPara.RequireSecuritySignature -eq 1) {
            $row.SMB_SigningRequiredIncoming = "Enabled"
            } else {
              $row.SMB_SigningRequiredIncoming = $SMBPara.RequireSecuritySignature   
        }

       # read the registry for SMB Signing parameters
 
     
         
         # make the parameters readable
         if ($SMBParaC.RequireSecuritySignature -eq 0) {
           $row.SMB_SigningRequiredOutgoing = "Disabled"
           } elseif ($SMBParaC.RequireSecuritySignature -eq 1) {
             $row.SMB_SigningRequiredOutgoing = "Enabled"
             } else {
               $row.SMB_SigningRequiredOutgoing = $SMBParaC.RequireSecuritySignature   
          }

      # read the registry for Link-local Multicast setting
    
      
      # make the parameters readable
        
        if ($LLMNR_On.EnableMulticast -eq 0) {
          $row.LLMNR = "Disabled"
          } elseif ($LLMNR_On.EnableMulticast -eq 1) {
            $row.LLMNR = "Enabled"
            } 
              elseif (-not $LLMNR_On.EnableMulticast) {
                $row.LLMNR = "OS Standard"
              }
                else {
                  $row.LLMNR = $LLMNR_On.EnableMulticast
                }
                  
      # SMB1 Feature installed?
     
      $row.SMBv1_Feature = $smb.state
      
      
      # LDAP Signing
      # make the parameter readable
      if ($ldapsign.ldapclientintegrity -eq 1) {
        $row.LDAP_Signing = 'Optional'
        }
        elseif ($ldapsign.ldapclientintegrity -eq 2) {
          $row.LDAP_Signing = 'Required'
          } elseif ($ldapsign.ldapclientintegrity -eq 0) {
            $row.LDAP_Signing = 'Off'
            } else {
             $row.LDAP_Signing = $ldapsign.ldapclientintegrity
            }

        # Netbios
        # make parameters readable
        if ($NetBios.TcpipNetbiosOptions -eq 0) {
        $row.NetBIOS = 'By DHCP'
        }
        elseif ($NetBios.TcpipNetbiosOptions -eq 1) {
          $row.NetBIOS = 'Enabled'
          } elseif ($ldapsign.ldapclientintegrity -eq 2) {
            $row.NetBIOS = 'Disabled'
            } else {
              $row.NetBIOS = $NetBios.TcpipNetbiosOptions
            }


        # NTLM - Lanmanager Authentication Level
        # make the parameter readable
        if ($NTLM_Level.lmcompatibilitylevel -eq 1) {
          $row.NTLM_level = 'Bad'
          } elseif ($NTLM_Level.lmcompatibilitylevel -eq 2) {
              $row.NTLM_level = 'NTLMv1 and lower'
            } elseif ($NTLM_Level.lmcompatibilitylevel -eq 3) {
                $row.NTLM_level = 'NTLMv2'
              } elseif ($NTLM_Level.lmcompatibilitylevel -eq 4) {
                  $row.NTLM_level = 'NTLMv2, Deny LM'
                } elseif ($NTLM_Level.lmcompatibilitylevel -eq 5) {
                    $row.NTLM_level = 'NTLMv2, Deny LM and NTLMv1'
                  } elseif (-not $NTLM_Level.lmcompatibilitylevel) {
                      $row.NTLM_level = 'OS Standard'
                    }   else {
                          $row.NTLM_level = $NTLM_Level.lmcompatibilitylevel
                      }


       # Restrict NTLM: Incoming and NTLM traffic

       #$RestrNTLMTraffic = Invoke-Command -computername $c -ErrorAction SilentlyContinue {Get-ItemProperty -Path "HKLM:System\CurrentControlSet\Control\Lsa\MSV1_0"}
       
       # make parameter readable: Incoming NTLM traffic
       if ($RestrNTLMTraffic.restrictreceivingntlmtraffic -eq 0) {
          $row.Restrict_NTLM_Incoming = 'Allow All'
          } elseif ($RestrNTLMTraffic.restrictreceivingntlmtraffic -eq 1) {
              $row.Restrict_NTLM_Incoming = 'Deny Domain Accounts'
            } elseif ($RestrNTLMTraffic.restrictreceivingntlmtraffic -eq 2) {
                $row.Restrict_NTLM_Incoming = 'Deny All Accounts'
              } elseif (-not $RestrNTLMTraffic.restrictreceivingntlmtraffic) {
                  $row.Restrict_NTLM_Incoming = 'Allow All'
                  } else {
                      $row.Restrict_NTLM_Incoming = $RestrNTLMTraffic.restrictreceivingntlmtraffic  
                    }

       # make parameter readable: Outgoing NTLM traffic
       if ($RestrNTLMTraffic.restrictsendingntlmtraffic -eq 0) {
          $row.Restrict_NTLM_Outgoing = 'Allow All'
          } elseif ($RestrNTLMTraffic.restrictsendingntlmtraffic -eq 1) {
              $row.Restrict_NTLM_Outgoing = 'Audit All'
            } elseif ($RestrNTLMTraffic.restrictsendingntlmtraffic -eq 2) {
                $row.Restrict_NTLM_Outgoing = 'Deny All'
              } elseif (-not $RestrNTLMTraffic.restrictsendingntlmtraffic) {
                  $row.Restrict_NTLM_Outgoing = 'Allow All'
                  } else {
                      $row.Restrict_NTLM_Outgoing = $RestrNTLMTraffic.restrictsendingntlmtraffic  
                      }
      }

      else {

        "Computer $c is no Windows Computer" | Write-Host -ForegroundColor Yellow

      }

      ""
      }

    # if it is not pingable

    else {
    "$c is not pingable" | Write-Host -ForegroundColor Red
    $row.Pingable = "No"
    }
    $table.Rows.Add($row)
}

# show results

$table | Format-Table -Autosize

# export results to csv

$table | Export-Csv -Path $csvpath\$csvname -Delimiter ';' -NoTypeInformation -Encoding UTF8

$table | Out-GridView


} else {
  Write-Host "Path for saving the results does not exist: $csvpath"
}