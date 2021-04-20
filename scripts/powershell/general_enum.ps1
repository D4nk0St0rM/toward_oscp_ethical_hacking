$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName


$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

# Uncomment for search required

#$Searcher.filter="samAccountType=268435456" # SAM_GROUP_OBJECT
#$Searcher.filter="samAccountType=268435457" #SAM_NON_SECURITY_GROUP_OBJECT
#$Searcher.filter="samAccountType=536870912" # SAM_ALIAS_OBJECT
#$Searcher.filter="samAccountType=536870913" # SAM_NON_SECURITY_ALIAS_OBJECT
#$Searcher.filter="samAccountType=805306368" # SAM_NORMAL_USER_ACCOUNT
#$Searcher.filter="samAccountType=805306369" # SAM_MACHINE_ACCOUNT
#$Searcher.filter="samAccountType=805306370" # SAM_TRUST_ACCOUNT
#$Searcher.filter="samAccountType=1073741824" # SAM_APP_BASIC_GROUP
#$Searcher.filter="samAccountType=1073741825" # SAM_APP_QUERY_GROUP
#$Searcher.filter="samAccountType=2147483647" # SAM_ACCOUNT_TYPE_MAX

#$Searcher.filter="name=zippy_rainbow"
#$Searcher.filter="(objectClass=Group)"
#$Searcher.filter="(name=Secret_Group)"
#$Searcher.filter="serviceprincipalname=*http*"


$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
	Foreach($prop in $obj.Properties)
	{
	$prop
	#$obj.Properties.member
	}
}
