rule EternalBlue_SMBv1_Trans2_Residue
{
    meta:
        description = "Residus SMBv1 compatibles avec une sequence EternalBlue"
        author = "Bilal Medj"
        context = "Memory forensic - exercice 5"

    strings:
        $smb_header = { FF 53 4D 42 }
        $tree_connect = { FF 53 4D 42 75 }
        $trans2 = { FF 53 4D 42 32 }
        $session_setup = { FF 53 4D 42 73 }
        $ipc = "\\IPC$" ascii wide
        $lanman = "LANMAN1.0" ascii

    condition:
        $smb_header and $tree_connect and $session_setup and #trans2 >= 2 and ($ipc or $lanman)
}

rule DoublePulsar_Implant_Kernel_Suspicion
{
    meta:
        description = "Suspicion d'implant DoublePulsar en memoire noyau"
        author = "Bilal"
        context = "Detection defensive, non confirmee dans ce dump"

    strings:
        $smb_header = { FF 53 4D 42 }
        $trans2 = { FF 53 4D 42 32 }
        $opcode_ping = { 51 }
        $opcode_exec = { 52 }
        $srv = "srv.sys" ascii wide
        $multiplex = "Multiplex" ascii wide

    condition:
        $smb_header and $trans2 and any of ($opcode_*) and ($srv or $multiplex)
}