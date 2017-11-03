<#
.SYNOPSIS
	This is a PowerShell script designed to set Auto login registry keys

.DESCRIPTION
	When run, this script will reference the Currently-LoggedIn.ps1 script to determine
    available user accounts, then perform a privelege escalation (assuming the supplied
    administrative credentials are correct) and add the necessary login information to
    the local system registry.  Once the system is logged off, or rebooted, it will
    automatically log back in with the designated user.

.PARAMETER
    None

.EXAMPLE
    This automatically assigns a new user account to auto-login to the machine
    	.\Auto-Login.ps1

.NOTES
    Revision History:
        04/19/2011 : Andy Arismendi - Created.
        09/29/2011 : Andy Arismendi - Changed to use LSA secrets to store password securely.
        05/01/2017 : Bryan Scarbrough - Changed from standalone script into function
        05/09/2017 : Bryan Scarbrough - Added dot sourced Currently-LoggedIn.ps1
                                      - Added automatic privelege escalation to run properly
                                      - Added AutoLogin function calls to script to run properly
                                        within elevated privilege session
        05/11/2017 : Bryan Scarbrough - Bypassed elevated privilege session and configured sleep time of
                                        script to run approximately 60 seconds before logoff
#>

. "C:\scripts\Currently-LoggedIn.ps1"
$next_user = ""
do {
	$next_user = get-random (Get-NextLogin "C:\scripts\txt-docs\internal_users.txt")
} while ($next_user = "")


    function AutoLogin ( $username, $password, $domain, $autologincount, $removelegalprompt ) {
        begin {
             
            [string] $WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            [string] $WinlogonBannerPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
         
            [string] $Enable = 1
            [string] $Disable = 0
             
            #region C# Code to P-invoke LSA LsaStorePrivateData function.
            Add-Type @"
                using System;
                using System.Collections.Generic;
                using System.Text;
                using System.Runtime.InteropServices;
         
                namespace ComputerSystem
                {
                    public class LSAutil
                    {
                        [StructLayout(LayoutKind.Sequential)]
                        private struct LSA_UNICODE_STRING
                        {
                            public UInt16 Length;
                            public UInt16 MaximumLength;
                            public IntPtr Buffer;
                        }
         
                        [StructLayout(LayoutKind.Sequential)]
                        private struct LSA_OBJECT_ATTRIBUTES
                        {
                            public int Length;
                            public IntPtr RootDirectory;
                            public LSA_UNICODE_STRING ObjectName;
                            public uint Attributes;
                            public IntPtr SecurityDescriptor;
                            public IntPtr SecurityQualityOfService;
                        }
         
                        private enum LSA_AccessPolicy : long
                        {
                            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
                            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
                            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
                            POLICY_TRUST_ADMIN = 0x00000008L,
                            POLICY_CREATE_ACCOUNT = 0x00000010L,
                            POLICY_CREATE_SECRET = 0x00000020L,
                            POLICY_CREATE_PRIVILEGE = 0x00000040L,
                            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
                            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
                            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
                            POLICY_SERVER_ADMIN = 0x00000400L,
                            POLICY_LOOKUP_NAMES = 0x00000800L,
                            POLICY_NOTIFICATION = 0x00001000L
                        }
         
                        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                        private static extern uint LsaRetrievePrivateData(
                                    IntPtr PolicyHandle,
                                    ref LSA_UNICODE_STRING KeyName,
                                    out IntPtr PrivateData
                        );
         
                        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                        private static extern uint LsaStorePrivateData(
                                IntPtr policyHandle,
                                ref LSA_UNICODE_STRING KeyName,
                                ref LSA_UNICODE_STRING PrivateData
                        );
         
                        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                        private static extern uint LsaOpenPolicy(
                            ref LSA_UNICODE_STRING SystemName,
                            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                            uint DesiredAccess,
                            out IntPtr PolicyHandle
                        );
         
                        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                        private static extern uint LsaNtStatusToWinError(
                            uint status
                        );
         
                        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                        private static extern uint LsaClose(
                            IntPtr policyHandle
                        );
         
                        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                        private static extern uint LsaFreeMemory(
                            IntPtr buffer
                        );
         
                        private LSA_OBJECT_ATTRIBUTES objectAttributes;
                        private LSA_UNICODE_STRING localsystem;
                        private LSA_UNICODE_STRING secretName;
         
                        public LSAutil(string key)
                        {
                            if (key.Length == 0)
                            {
                                throw new Exception("Key length zero");
                            }
         
                            objectAttributes = new LSA_OBJECT_ATTRIBUTES();
                            objectAttributes.Length = 0;
                            objectAttributes.RootDirectory = IntPtr.Zero;
                            objectAttributes.Attributes = 0;
                            objectAttributes.SecurityDescriptor = IntPtr.Zero;
                            objectAttributes.SecurityQualityOfService = IntPtr.Zero;
         
                            localsystem = new LSA_UNICODE_STRING();
                            localsystem.Buffer = IntPtr.Zero;
                            localsystem.Length = 0;
                            localsystem.MaximumLength = 0;
         
                            secretName = new LSA_UNICODE_STRING();
                            secretName.Buffer = Marshal.StringToHGlobalUni(key);
                            secretName.Length = (UInt16)(key.Length * UnicodeEncoding.CharSize);
                            secretName.MaximumLength = (UInt16)((key.Length + 1) * UnicodeEncoding.CharSize);
                        }
         
                        private IntPtr GetLsaPolicy(LSA_AccessPolicy access)
                        {
                            IntPtr LsaPolicyHandle;
         
                            uint ntsResult = LsaOpenPolicy(ref this.localsystem, ref this.objectAttributes, (uint)access, out LsaPolicyHandle);
         
                            uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                            if (winErrorCode != 0)
                            {
                                throw new Exception("LsaOpenPolicy failed: " + winErrorCode);
                            }
         
                            return LsaPolicyHandle;
                        }
         
                        private static void ReleaseLsaPolicy(IntPtr LsaPolicyHandle)
                        {
                            uint ntsResult = LsaClose(LsaPolicyHandle);
                            uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                            if (winErrorCode != 0)
                            {
                                throw new Exception("LsaClose failed: " + winErrorCode);
                            }
                        }
         
                        public void SetSecret(string value)
                        {
                            LSA_UNICODE_STRING lusSecretData = new LSA_UNICODE_STRING();
         
                            if (value.Length > 0)
                            {
                                //Create data and key
                                lusSecretData.Buffer = Marshal.StringToHGlobalUni(value);
                                lusSecretData.Length = (UInt16)(value.Length * UnicodeEncoding.CharSize);
                                lusSecretData.MaximumLength = (UInt16)((value.Length + 1) * UnicodeEncoding.CharSize);
                            }
                            else
                            {
                                //Delete data and key
                                lusSecretData.Buffer = IntPtr.Zero;
                                lusSecretData.Length = 0;
                                lusSecretData.MaximumLength = 0;
                            }
         
                            IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_CREATE_SECRET);
                            uint result = LsaStorePrivateData(LsaPolicyHandle, ref secretName, ref lusSecretData);
                            ReleaseLsaPolicy(LsaPolicyHandle);
         
                            uint winErrorCode = LsaNtStatusToWinError(result);
                            if (winErrorCode != 0)
                            {
                                throw new Exception("StorePrivateData failed: " + winErrorCode);
                            }
                        }
                    }
                }
"@
            #endregion
        }
         
        process {
         
            try {
                $ErrorActionPreference = "Stop"
                 
                $decryptedPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                )
         
                if ($BackupFile) {
                        # Initialize the hash table with a string comparer to allow case sensitive keys.
                        # This allows differentiation between the winlogon and system policy logon banner strings.
                    $OrigionalSettings = New-Object System.Collections.Hashtable ([system.stringcomparer]::CurrentCulture)
                     
                    $OrigionalSettings.AutoAdminLogon = (Get-ItemProperty $WinlogonPath ).AutoAdminLogon
                    $OrigionalSettings.ForceAutoLogon = (Get-ItemProperty $WinlogonPath).ForceAutoLogon
                    $OrigionalSettings.DefaultUserName = (Get-ItemProperty $WinlogonPath).DefaultUserName
                    $OrigionalSettings.DefaultDomainName = (Get-ItemProperty $WinlogonPath).DefaultDomainName
                    $OrigionalSettings.DefaultPassword = (Get-ItemProperty $WinlogonPath).DefaultPassword
                    $OrigionalSettings.AutoLogonCount = (Get-ItemProperty $WinlogonPath).AutoLogonCount
                     
                        # The winlogon logon banner settings.
                    $OrigionalSettings.LegalNoticeCaption = (Get-ItemProperty $WinlogonPath).LegalNoticeCaption
                    $OrigionalSettings.LegalNoticeText = (Get-ItemProperty $WinlogonPath).LegalNoticeText
                     
                        # The system policy logon banner settings.
                    $OrigionalSettings.legalnoticecaption = (Get-ItemProperty $WinlogonBannerPolicyPath).legalnoticecaption
                    $OrigionalSettings.legalnoticetext = (Get-ItemProperty $WinlogonBannerPolicyPath).legalnoticetext
                     
                    $OrigionalSettings | Export-Clixml -Depth 10 -Path $BackupFile
                }
                 
                    # Store the password securely.
                $lsaUtil = New-Object ComputerSystem.LSAutil -ArgumentList "DefaultPassword"
                $lsaUtil.SetSecret($decryptedPass)
         
                    # Store the autologon registry settings.
                Set-ItemProperty -Path $WinlogonPath -Name AutoAdminLogon -Value $Enable -Force
         
                Set-ItemProperty -Path $WinlogonPath -Name DefaultUserName -Value $Username -Force
                Set-ItemProperty -Path $WinlogonPath -Name DefaultDomainName -Value $Domain -Force
				
				Set-ItemProperty -Path $WinlogonPath -Name ForceAutoLogin -Value 1 -Force
         
                if ($AutoLogonCount) {
                    Set-ItemProperty -Path $WinlogonPath -Name AutoLogonCount -Value $AutoLogonCount -Force
                } else {
                    Remove-ItemProperty -Path $WinlogonPath -Name AutoLogonCount -ErrorAction SilentlyContinue
                }
         
                if ($RemoveLegalPrompt) {
                    Set-ItemProperty -Path $WinlogonPath -Name LegalNoticeCaption -Value $null -Force
                    Set-ItemProperty -Path $WinlogonPath -Name LegalNoticeText -Value $null -Force
                     
                    Set-ItemProperty -Path $WinlogonBannerPolicyPath -Name legalnoticecaption -Value $null -Force
                    Set-ItemProperty -Path $WinlogonBannerPolicyPath -Name legalnoticetext -Value $null -Force
                }
            } catch {
                throw 'Failed to set auto logon. The error was: "{0}".' -f $_
            }
         
        }
    }
    
    # Password statically assigned for all users in exercise network
    $pass = ConvertTo-SecureString '1qaz2wsx#' -AsPlainText -Force
    $dom = $env:UserDomain
    $login_count = 1
    $remove_banner = 1

    # Call AutoLogin function using all necessary variables
    #AutoLogin $args[0] $pass $dom $login_count $remove_banner
    AutoLogin $next_user $pass $dom $login_count $remove_banner


<#

  # Pass next_user variable determined at the beginning into the script block
} -Args $next_user

Remove-PSSession $elevated_sess

#>
