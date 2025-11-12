<#
    .SYNOPSIS
    Generates all permutations of n objects with the heap algorithm.
    .DESCRIPTION
    Generates all permutations of n objects with the heap algorithm.
    .PARAMETER ToPermute
    Specifies the array with values to permute.
    For example (string): 'A','B','C'
    .OUTPUTS
    All permutations of the input array.
    .EXAMPLE
    PS> Permutation.ps1 -ToPermute 1,2,3
    1,2,3
    2,1,3
    3,1,2
    1,3,2
    2,3,1
    3,2,1
    .LINK
    https://gist.github.com/Calvindd2f
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [Array]$ToPermute = @('A','B','C')
)

function Add-Permutation {
    [CmdletBinding()]
    param(
        [Array]$ToPermute,
        [int]$ArrLength
    )
    if ($ArrLength -eq 1) {
        # Print permutation
        $ToPermute -join ','
    } else {
        for ($i = 0; $i -lt $ArrLength; $i++) {
            Add-Permutation -ToPermute $ToPermute -ArrLength ($ArrLength - 1)
            # If size is even, swap i-th and (ArrLength - 1)-th element
            if ($ArrLength % 2 -eq 0) {
                $Temp = $ToPermute[$i]
                $ToPermute[$i] = $ToPermute[($ArrLength - 1)]
                $ToPermute[($ArrLength - 1)] = $Temp
            # If size is odd, swap 0-th and (ArrLength - 1)-th element
            } else {
                $Temp = $ToPermute[0]
                $ToPermute[0] = $ToPermute[($ArrLength - 1)]
                $ToPermute[($ArrLength - 1)] = $Temp
            }
        }
    }
}

Add-Permutation -ToPermute $ToPermute -ArrLength $ToPermute.Length