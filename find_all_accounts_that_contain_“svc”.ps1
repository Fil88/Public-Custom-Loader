#Build LDAP filter to find service accounts based on naming conventions
$ldapFilter = "(&(objectclass=Person)(cn=*svc*))"
$domain = New-Object System.DirectoryServices.DirectoryEntry
$search = New-Object System.DirectoryServices.DirectorySearcher
$search.SearchRoot = $domain
$search.PageSize = 1000
$search.Filter = $ldapFilter
$search.SearchScope = "Subtree"

#Add list of properties to search for
$objProperties = "name"
Foreach ($i in $objProperties){$search.PropertiesToLoad.Add($i)}

#Execute Search
$results = $search.FindAll()
#Display values from the returned objects
foreach ($result in $results)
{
    $userEntry = $result.GetDirectoryEntry()
    Write-Host "User Name = " $userEntry.name
    Write-Host ""   
}:


$ldapFilter = "(&(objectCategory=person)(objectClass=user))"