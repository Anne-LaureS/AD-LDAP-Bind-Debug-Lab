<#
.SYNOPSIS
    Tente un bind LDAP et traduit l'erreur AD étendue en diagnostic humain — le pendant
    "auth legacy" du debug SSO moderne (OIDC/SAML) fait dans Okta-SSO-Debug-Lab.

.DESCRIPTION
    Une application qui authentifie ses utilisateurs par bind LDAP simple reçoit, en cas
    d'échec, une exception .NET dont le message contient un code AD étendu au format
    "data XXX" (ex: "80090308: LdapErr: ... data 52e, v...") — ce script extrait ce code et
    affiche la cause probable/remédiation au lieu du message brut, à la manière d'un runbook
    de debug plutôt que d'un simple succès/échec.

    Utilise System.DirectoryServices.Protocols (comme LDAP-App-Role-Audit) plutôt que le module
    ActiveDirectory : on simule ici un client applicatif qui s'authentifie, pas un outil
    d'administration.

.PARAMETER BindDN
    DN complet à utiliser pour le bind (ex: "uid=jdupont,ou=RCI,ou=People,o=renault" ou, sur ce
    lab, "jdupont@society.local" fonctionne aussi via UPN). Omis avec -CheckAnonymous.

.PARAMETER Password
    Mot de passe du compte, en SecureString. Omis avec -CheckAnonymous.

.PARAMETER LdapServer
    Contrôleur de domaine cible. DC1.society.local par défaut (lab de référence du portfolio).

.PARAMETER Port
    Port LDAP. 389 par défaut, 636 par défaut si -UseTls est utilisé sans préciser -Port.

.PARAMETER UseTls
    Bind via LDAPS (SSL/TLS) plutôt qu'en clair — fait apparaître une éventuelle erreur de
    confiance de certificat, distincte des codes d'erreur AD applicatifs.

.PARAMETER CheckAnonymous
    Tente un bind anonyme (sans DN ni mot de passe) au lieu d'un bind authentifié, puis une
    recherche derrière — un bind anonyme qui réussit est le comportement PAR DÉFAUT du
    protocole LDAP/AD, pas un problème en soi. Ce qui compte est de savoir si cette session
    anonyme peut ensuite LIRE du contenu réel de l'annuaire (risque réel) ou pas
    (comportement par défaut inoffensif).

.EXAMPLE
    .\Test-LdapBind.ps1 -BindDN "jdupont@society.local" -Password (Read-Host -AsSecureString)

.EXAMPLE
    .\Test-LdapBind.ps1 -LdapServer DC1.society.local -CheckAnonymous

.EXAMPLE
    .\Test-LdapBind.ps1 -BindDN "jdupont@society.local" -Password (Read-Host -AsSecureString) -UseTls
#>

[CmdletBinding(DefaultParameterSetName = 'Authenticated')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Authenticated')]
    [string]$BindDN,

    [Parameter(Mandatory, ParameterSetName = 'Authenticated')]
    [System.Security.SecureString]$Password,

    [Parameter(ParameterSetName = 'Anonymous')]
    [switch]$CheckAnonymous,

    [string]$LdapServer = "DC1.society.local",

    [int]$Port,

    [switch]$UseTls
)

Add-Type -AssemblyName System.DirectoryServices.Protocols

# Table de correspondance des codes d'erreur AD étendus (RFC 4511 + extensions Microsoft) —
# le code "data XXX" est une sous-erreur Windows au sein d'un résultat LDAP générique
# (le plus souvent invalidCredentials), qui ne dit sinon rien sur la cause réelle.
$adErrorCodes = @{
    '525' = "Utilisateur introuvable — DN/identifiant mal formé ou compte inexistant"
    '52e' = "Identifiants invalides — mot de passe incorrect (ou DN correct mais mauvais mot de passe)"
    '530' = "Connexion refusée à cette heure (restriction horaire du compte)"
    '531' = "Connexion refusée depuis ce poste (restriction de station de travail)"
    '532' = "Mot de passe expiré"
    '533' = "Compte désactivé"
    '701' = "Compte expiré (date d'expiration dépassée)"
    '773' = "Mot de passe à changer obligatoirement à la prochaine connexion"
    '775' = "Compte verrouillé (trop de tentatives échouées)"
}

function Get-AdErrorDiagnosis {
    param([string]$ErrorMessage)
    if ($ErrorMessage -match 'data ([0-9a-f]{2,4})') {
        $code = $Matches[1]
        if ($adErrorCodes.ContainsKey($code)) {
            return [PSCustomObject]@{ Code = $code; Diagnosis = $adErrorCodes[$code] }
        }
        return [PSCustomObject]@{ Code = $code; Diagnosis = "Code AD non catalogué — voir la référence Microsoft des codes d'erreur LDAP" }
    }
    if ($ErrorMessage -match 'certificate|trust|SSL|TLS') {
        return [PSCustomObject]@{ Code = ""; Diagnosis = "Erreur de confiance du certificat LDAPS — certificat manquant, auto-signé ou non approuvé par ce poste" }
    }
    if ($ErrorMessage -match "n'est pas disponible|unavailable|server down|active refusé|connection refused") {
        return [PSCustomObject]@{ Code = ""; Diagnosis = "Serveur LDAP injoignable sur ce port — pour du LDAPS (636), signifie le plus souvent qu'aucun certificat LDAPS n'est configuré sur ce contrôleur de domaine, donc le service n'écoute pas du tout sur ce port (plus fondamental qu'un certificat simplement non approuvé)" }
    }
    return [PSCustomObject]@{ Code = ""; Diagnosis = "Pas de code AD reconnu dans le message — voir l'erreur brute ci-dessous" }
}

$result = [PSCustomObject]@{
    LdapServer    = $LdapServer
    Port          = 0
    Mode          = if ($CheckAnonymous) { "Anonyme" } else { "Authentifié" }
    UseTls        = [bool]$UseTls
    Success       = $false
    ErrorCode     = ""
    Diagnosis     = ""
    RawError      = ""
}

try {
    if (-not $PSBoundParameters.ContainsKey('Port')) {
        $Port = if ($UseTls) { 636 } else { 389 }
    }
    $result.Port = $Port

    $ldapIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port)
    $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($ldapIdentifier)
    $ldapConnection.SessionOptions.ProtocolVersion = 3
    $ldapConnection.SessionOptions.SecureSocketLayer = [bool]$UseTls

    if ($CheckAnonymous) {
        $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
    }
    else {
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Password))
        $ldapConnection.Credential = New-Object System.Net.NetworkCredential($BindDN, $plainPassword)
        $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
    }

    $ldapConnection.Bind()
    $result.Success = $true

    if ($CheckAnonymous) {
        # Un bind anonyme qui réussit est le comportement PAR DÉFAUT du protocole LDAP (RFC
        # 4513) et d'AD — ce que la sécurité restreint réellement par défaut, c'est la LECTURE
        # qui suit, pas le bind lui-même. S'arrêter au bind réussi pour crier "mauvaise
        # configuration" serait un faux positif : il faut vérifier si une recherche anonyme
        # renvoie vraiment du contenu de l'annuaire.
        $rootDseRequest = New-Object System.DirectoryServices.Protocols.SearchRequest("", "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base, "defaultNamingContext")
        $rootDseResponse = $ldapConnection.SendRequest($rootDseRequest)
        $namingContext = $rootDseResponse.Entries[0].Attributes["defaultNamingContext"][0]

        $canRead = $false
        try {
            $probeRequest = New-Object System.DirectoryServices.Protocols.SearchRequest($namingContext, "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Subtree, "name")
            $probeRequest.SizeLimit = 1
            $probeResponse = $ldapConnection.SendRequest($probeRequest)
            $canRead = ($probeResponse.Entries.Count -gt 0)
        }
        catch {
            $canRead = $false
        }

        if ($canRead) {
            Write-Host "=== Bind anonyme ACCEPTÉ et lecture du contenu de l'annuaire possible par $LdapServer`:$Port — RISQUE RÉEL ===" -ForegroundColor Red
            $result.Diagnosis = "Bind anonyme accepté ET lecture anonyme du contenu de l'annuaire possible — mauvaise configuration de sécurité réelle, pas seulement le bind par défaut"
        }
        else {
            Write-Host "=== Bind anonyme accepté (normal) mais lecture du contenu refusée par $LdapServer`:$Port — comportement par défaut, pas un risque ===" -ForegroundColor Green
            $result.Diagnosis = "Bind anonyme accepté (comportement RFC/AD par défaut) mais aucune lecture possible ensuite — pas un risque de sécurité en soi"
        }
    }
    else {
        Write-Host "=== Bind réussi : $BindDN sur $LdapServer`:$Port ===" -ForegroundColor Green
        $result.Diagnosis = "Bind réussi — identifiants et configuration corrects"
    }
}
catch {
    # .Bind() appelé comme méthode .NET directe : si elle lève, PowerShell enveloppe
    # l'exception réelle dans une MethodInvocationException dont le .Message est un texte
    # générique et LOCALISÉ (ex: "Les informations d'identification fournies ne sont pas
    # valides"), sans le code "data XXX". La vraie LdapException — avec le détail serveur
    # complet — est dans .InnerException, et son code est dans la propriété
    # ServerErrorMessage, pas Message. Sans ça, le diagnostic ne trouve jamais aucun code sous
    # un OS/.NET localisé en français.
    $innerException = $_.Exception.InnerException
    $diagnosticText = $_.Exception.Message
    if ($innerException) {
        if ($innerException.PSObject.Properties.Name -contains 'ServerErrorMessage' -and $innerException.ServerErrorMessage) {
            $diagnosticText = $innerException.ServerErrorMessage
        }
        else {
            $diagnosticText = $innerException.Message
        }
    }
    $result.RawError = $diagnosticText

    if ($CheckAnonymous) {
        Write-Host "=== Bind anonyme REFUSÉ par $LdapServer`:$Port — comportement attendu ===" -ForegroundColor Green
        $result.Success = $false
        $result.Diagnosis = "Bind anonyme correctement refusé"
    }
    else {
        $diag = Get-AdErrorDiagnosis -ErrorMessage $diagnosticText
        $result.ErrorCode = $diag.Code
        $result.Diagnosis = $diag.Diagnosis
        Write-Host "=== Échec du bind : $BindDN sur $LdapServer`:$Port ===" -ForegroundColor Red
        Write-Host "Diagnostic : $($diag.Diagnosis)" -ForegroundColor Yellow
        if ($diag.Code) { Write-Host "Code AD : $($diag.Code)" -ForegroundColor Yellow }
        Write-Host "Erreur brute : $diagnosticText" -ForegroundColor DarkGray
    }
}

$result
