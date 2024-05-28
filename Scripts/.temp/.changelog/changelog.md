# Remove the $areyouconnected assertion

**Removed Assertion Entirely**

Will detail a bit more later but this is a genuine product killer.

From root of module;

```powershell
$files=gci -R
foreach ($f in $files){cat $f | findstr.exe /i "connected"}

# Manually removed each outputted $areyouconnected with only one remaining; the az subscription one
```


----------------------------------------------

