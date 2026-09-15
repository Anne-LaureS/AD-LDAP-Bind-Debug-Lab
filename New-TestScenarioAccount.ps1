<#
.SYNOPSIS
    Crée (ou réutilise) un compte de test jetable et le place dans un état de panne donné,
    pour démontrer Test-LdapBind.ps1 sans jamais toucher à un compte réel.

.DESCRIPTION
    Sert uniquement à préparer les scénarios du runbook (procedure-debug-bind.md) : un compte
    créé ici n'a aucune vocation à représenter une vraie identité (contrairement à
    IAM-JML-Lifecycle) — il n'a pas de groupe, pas de département, juste un état de compte
    permettant de provoquer un code d'erreur AD précis au bind.

.PARAMETER FirstName
    Prénom du compte de test.

.PARAMETER LastName
    Nom du compte de test.

.PARAMETER Password
    Mot de passe à poser sur le compte (SecureString) — choisi par vous plutôt que généré
    aléatoirement, pour pouvoir le réutiliser dans plusieurs commandes Test-LdapBind.ps1.

.PARAMETER Scenario
    État de panne à provoquer : Disabled, ExpiredAccount, ExpiredPassword, ou Locked (ce
    dernier appelle réellement Test-LdapBind.ps1 5 fois avec un mauvais mot de passe pour
    déclencher le verrouillage AD, plutôt que de positionner un attribut directement).

.PARAMETER Server
    Contrôleur de domaine cible. DC1.society.local par défaut.

.PARAMETER TestOU
    OU où créer le compte. OU=Utilisateurs-Test,DC=society,DC=local par défaut — les comptes
    créés ici sont, par nature, des comptes de test jetables.

.PARAMETER Credential
    Identifiants pour le bind AD (compte admin). Si omis, demandés interactivement.

.EXAMPLE
    .\New-TestScenarioAccount.ps1 -FirstName "Bind" -LastName "Locked" -Password (Read-Host -AsSecureString) -Scenario Locked
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FirstName,

    [Parameter(Mandatory)]
    [string]$LastName,

    [Parameter(Mandatory)]
    [System.Security.SecureString]$Password,

    [Parameter(Mandatory)]
    [ValidateSet('Disabled', 'ExpiredAccount', 'ExpiredPassword', 'Locked')]
    [string]$Scenario,

    [string]$Server = "DC1.society.local",

    [string]$TestOU = "OU=Utilisateurs-Test,DC=society,DC=local",

    [System.Management.Automation.PSCredential]$Credential
)

function Remove-Diacritics {
    param([string]$Text)
    if (-not $Text) { return "" }
    $normalized = $Text.Normalize([Text.NormalizationForm]::FormD)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $normalized.ToCharArray()) {
        if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

$result = [PSCustomObject]@{
    FirstName      = $FirstName
    LastName       = $LastName
    SamAccountName = ""
    Scenario       = $Scenario
    Status         = "Failed"
    Error          = ""
}

try {
    if (-not $Credential) {
        $Credential = Get-Credential -Message "Identifiants pour le bind sur $Server"
    }

    $first = (Remove-Diacritics $FirstName).Substring(0, 1)
    $last  = (Remove-Diacritics $LastName) -replace '[^A-Za-z]', ''
    $samAccountName = ($first + $last).ToLowerInvariant()
    $result.SamAccountName = $samAccountName

    $existingUser = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -Server $Server -Credential $Credential -ErrorAction SilentlyContinue

    if (-not $existingUser) {
        try {
            New-ADUser `
                -Name "$FirstName $LastName" `
                -GivenName $FirstName `
                -Surname $LastName `
                -SamAccountName $samAccountName `
                -UserPrincipalName "$samAccountName@society.local" `
                -Path $TestOU `
                -AccountPassword $Password `
                -Enabled $true `
                -Server $Server `
                -Credential $Credential `
                -ErrorAction Stop
            Write-Host "Compte de test créé : $samAccountName" -ForegroundColor Green
        }
        catch {
            # New-ADUser peut créer l'objet AVANT d'échouer sur le mot de passe (ex: politique
            # de complexité non respectée) — un objet à moitié configuré resterait sinon dans
            # l'annuaire et fausserait silencieusement toutes les tentatives suivantes (la
            # branche "compte existant" ci-dessous le retrouverait et tenterait de le réparer
            # au lieu de repartir propre). On nettoie ce résidu avant de remonter l'erreur.
            Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -Server $Server -Credential $Credential -ErrorAction SilentlyContinue |
                Remove-ADUser -Server $Server -Credential $Credential -Confirm:$false -ErrorAction SilentlyContinue
            throw
        }
    }
    else {
        # Repart d'un état propre avant d'appliquer le scénario demandé — un compte réutilisé
        # d'un scénario précédent (ex: désactivé) fausserait le test suivant. -ErrorAction Stop
        # partout : ces cmdlets AD lèvent des exceptions terminales qui contournent
        # SilentlyContinue (même piège que dans IAM-JML-Lifecycle) — les avaler ferait échouer
        # une étape plus tard avec un message sans rapport avec la vraie cause.
        Set-ADAccountControl -Identity $samAccountName -Server $Server -Credential $Credential -Enabled $true -AccountNotDelegated $false -ErrorAction Stop
        Enable-ADAccount -Identity $samAccountName -Server $Server -Credential $Credential -ErrorAction Stop
        Clear-ADAccountExpiration -Identity $samAccountName -Server $Server -Credential $Credential -ErrorAction Stop
        Unlock-ADAccount -Identity $samAccountName -Server $Server -Credential $Credential -ErrorAction Stop
        Set-ADAccountPassword -Identity $samAccountName -NewPassword $Password -Reset -Server $Server -Credential $Credential -ErrorAction Stop
        Write-Host "Compte de test existant réinitialisé : $samAccountName" -ForegroundColor Yellow
    }

    switch ($Scenario) {
        'Disabled' {
            Disable-ADAccount -Identity $samAccountName -Server $Server -Credential $Credential
        }
        'ExpiredAccount' {
            Set-ADAccountExpiration -Identity $samAccountName -DateTime (Get-Date).AddDays(-1) -Server $Server -Credential $Credential
        }
        'ExpiredPassword' {
            # pwdLastSet=0 est l'équivalent brut de la case "L'utilisateur doit changer son mot
            # de passe à la prochaine ouverture de session" dans ADUC.
            Set-ADUser -Identity $samAccountName -Server $Server -Credential $Credential -Replace @{ pwdLastSet = 0 }
        }
        'Locked' {
            # Le verrouillage AD n'est pas un attribut à positionner directement : c'est un état
            # qui résulte de LockoutThreshold échecs de bind consécutifs (5 sur ce lab). On
            # provoque donc le verrouillage en rejouant le vrai scénario côté client, avec un
            # mot de passe volontairement faux, plutôt que de simuler l'effet.
            $wrongPassword = ConvertTo-SecureString "MotDePasseSciemmentFaux1!" -AsPlainText -Force
            for ($i = 1; $i -le 5; $i++) {
                & (Join-Path $PSScriptRoot "Test-LdapBind.ps1") -BindDN "$samAccountName@society.local" -Password $wrongPassword -LdapServer $Server | Out-Null
            }
        }
    }

    $result.Status = "Success"
    Write-Host "=== Scénario '$Scenario' appliqué à $samAccountName ===" -ForegroundColor Green
}
catch {
    $result.Error = $_.Exception.Message
    Write-Host "ERREUR : $($_.Exception.Message)" -ForegroundColor Red
}

$result
