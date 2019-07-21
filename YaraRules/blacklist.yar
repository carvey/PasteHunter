rule blacklist
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "#EXTINF:" nocase // IPTV stream Lists.
        $b = "--app-name=LeagueClient" nocase // League of Legends Debug Log
        $c = "common.application_name: LeagueClient" // League of Legends Debug Log
        $d = /java\.(util|lang|io)/ // Minecraft and java errors
        $e = "Traceback (most recent call last)"
        $f = /define\(.*?\)|require_once\(.*?\)/
        $g = "Technic Launcher is starting" // Minecraft mod dumps
        $h = "OTL logfile created on" // 
        $i = "Rimworld" nocase // rimworld debug logs
        $j = "DOTA_" nocase //dota debug logs
        $vrp = "imagicthecat" nocase //role playing framwork db structure
        $chocolatey = "chocolateyInstall.ps1" nocase
    condition:
        any of them

}
