/*
    SS Forensic - Built-in YARA rule set
    These rules tag known-bad strings from common Minecraft cheat clients
    and generic Java injection patterns. Add custom rules in this folder.
*/

rule MC_Cheat_Vape : cheat
{
    meta:
        author      = "SS Forensic"
        description = "Vape / Vape Lite / Vape V4 cheat client"
    strings:
        $a = "vape.gg"             nocase ascii wide
        $b = "Vape V4"             nocase ascii wide
        $c = "VapeClient"          nocase ascii wide
        $d = "vape.cool"           nocase ascii wide
    condition:
        any of them
}

rule MC_Cheat_LiquidBounce : cheat
{
    meta:
        description = "LiquidBounce hacked client"
    strings:
        $a = "LiquidBounce"        nocase ascii wide
        $b = "ccbluex"             nocase ascii wide
        $c = "net.ccbluex"         nocase ascii wide
    condition:
        any of them
}

rule MC_Cheat_Wurst : cheat
{
    meta:
        description = "Wurst hacked client"
    strings:
        $a = "WurstClient"         nocase ascii wide
        $b = "wurstclient.net"     nocase ascii wide
        $c = "net.wurstclient"     nocase ascii wide
    condition:
        any of them
}

rule MC_Cheat_Impact : cheat
{
    meta:
        description = "Impact hacked client"
    strings:
        $a = "Impact Client"       nocase ascii wide
        $b = "impactclient.net"    nocase ascii wide
        $c = "me.zeroeightsix"     nocase ascii wide
    condition:
        any of them
}

rule MC_Cheat_Aristois : cheat
{
    meta:
        description = "Aristois cheat client"
    strings:
        $a = "Aristois"            nocase ascii wide
        $b = "aristois.net"        nocase ascii wide
    condition:
        any of them
}

rule MC_Cheat_Meteor : cheat
{
    meta:
        description = "Meteor Client"
    strings:
        $a = "meteorclient"        nocase ascii wide
        $b = "Meteor Client"       nocase ascii wide
        $c = "meteordevelopment"   nocase ascii wide
    condition:
        any of them
}

rule MC_Cheat_Pyro : cheat
{
    meta:
        description = "Pyro / Slinky cheat clients (common ghost clients)"
    strings:
        $a = "PyroClient"          nocase ascii wide
        $b = "slinkyclient"        nocase ascii wide
        $c = "pyro.gg"             nocase ascii wide
    condition:
        any of them
}

rule Generic_Cheat_Strings : cheat
{
    meta:
        description = "Generic strings frequently found in cheat clients"
    strings:
        $a = "Killaura"            nocase ascii wide
        $b = "Aimbot"              nocase ascii wide
        $c = "ESP"                 fullword ascii wide
        $d = "Fly Hack"            nocase ascii wide
        $e = "Reach"               fullword ascii wide
        $f = "Anti Knockback"      nocase ascii wide
        $g = "Anti-Knockback"      nocase ascii wide
        $h = "AutoClicker"         nocase ascii wide
        $i = "Triggerbot"          nocase ascii wide
    condition:
        3 of them
}

rule Java_Native_Agent : cheat
{
    meta:
        description = "JVM native agent loading - common cheat injection vector"
    strings:
        $a = "Agent_OnLoad"        ascii wide
        $b = "Agent_OnAttach"      ascii wide
        $c = "JNI_OnLoad"          ascii wide
        $d = "VirtualMachine.attach" ascii wide
        $e = "Instrumentation"     ascii wide
    condition:
        ($a or $b) and ($d or $e)
}

rule Suspicious_DLL_Injector : cheat
{
    meta:
        description = "Generic DLL injection markers"
    strings:
        $a = "VirtualAllocEx"      ascii wide
        $b = "WriteProcessMemory"  ascii wide
        $c = "CreateRemoteThread"  ascii wide
        $d = "LoadLibraryA"        ascii wide
        $e = "NtMapViewOfSection"  ascii wide
    condition:
        3 of them
}
