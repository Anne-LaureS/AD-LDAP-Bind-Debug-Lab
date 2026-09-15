# 🔐 AD LDAP Bind Debug Lab

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![ActiveDirectory](https://img.shields.io/badge/Active%20Directory-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![LDAP](https://img.shields.io/badge/LDAP-Legacy%20Auth-0d1117?style=for-the-badge)

Labo de debug pour l'authentification **legacy** par bind LDAP simple contre Active Directory —
le counterpart de [Okta-SSO-Debug-Lab](https://github.com/Anne-LaureS/Okta-SSO-Debug-Lab) (OIDC/SAML)
pour les applications qui authentifient encore leurs utilisateurs directement contre l'annuaire
(VPN, Wi-Fi RADIUS, applis internes) plutôt que via un SSO fédéré — un pattern toujours très
répandu en entreprise à côté du SSO moderne.

Plutôt que de renvoyer le message d'erreur .NET brut, ce labo traduit les codes d'erreur AD
étendus (`data XXX`) en diagnostic humain, avec une procédure pour reproduire chaque panne
courante à la demande sur un compte de test jetable.

Testé contre le même lab Active Directory (Windows Server 2022, `DC1.society.local`) que
LDAP-App-Role-Audit et IAM-JML-Lifecycle.

## ⚙️ Les scripts

| Script | Rôle |
|---|---|
| [`Test-LdapBind.ps1`](Test-LdapBind.ps1) | Tente un bind (authentifié, anonyme, ou LDAPS) et traduit l'erreur en diagnostic |
| [`New-TestScenarioAccount.ps1`](New-TestScenarioAccount.ps1) | Prépare un compte de test jetable dans un état de panne donné (désactivé, expiré, verrouillé, mot de passe à changer) |

Le détail de chaque scénario (commande, sortie attendue, remédiation) est dans
[`procedure-debug-bind.md`](procedure-debug-bind.md) — le vrai contenu de ce repo est ce
runbook, les scripts ne font qu'automatiser sa reproduction.

## ▶️ Utilisation

```powershell
# Bind authentifié normal
.\Test-LdapBind.ps1 -BindDN "jdupont@society.local" -Password (Read-Host -AsSecureString)

# Bind anonyme (vérifie qu'il est bien refusé)
.\Test-LdapBind.ps1 -LdapServer DC1.society.local -CheckAnonymous

# Bind via LDAPS
.\Test-LdapBind.ps1 -BindDN "jdupont@society.local" -Password (Read-Host -AsSecureString) -UseTls
```

Ne jamais tester une panne (compte désactivé, verrouillé...) sur un compte réel — préparer un
compte jetable dédié :

```powershell
$testPwd = Read-Host -AsSecureString -Prompt "Mot de passe du compte de test"
.\New-TestScenarioAccount.ps1 -FirstName "Bind" -LastName "Test" -Password $testPwd -Scenario Locked
```

(`$pwd` est une variable automatique PowerShell — le répertoire courant — évitez ce nom, un
`cd` l'écraserait silencieusement.)

Voir [`procedure-debug-bind.md`](procedure-debug-bind.md) pour les 8 scénarios complets
(identifiants invalides, compte désactivé/expiré/verrouillé, mot de passe à changer, bind
anonyme, LDAPS sans certificat, mauvais format de DN).

## 📊 Exemple de bout en bout

Les 8 scénarios du runbook ont été exécutés pour de vrai contre `DC1.society.local` — captures
et résultats réels dans [`procedure-debug-bind.md`](procedure-debug-bind.md). Deux résultats
sont différents de ce qui était prévu au départ, corrigés/documentés tels quels plutôt que
forcés à correspondre à l'hypothèse initiale :

- **Bind anonyme** : accepté par défaut (normal, RFC LDAP), mais la lecture du contenu de
  l'annuaire ensuite est correctement refusée — pas un risque sur ce lab. Le script a été
  corrigé pour tester la lecture réelle plutôt que de s'arrêter au bind seul (un bind anonyme
  réussi n'est pas en soi une faute de sécurité).
- **Mauvais format de DN** : un `sAMAccountName` nu (`btest` au lieu d'un UPN/DN complet)
  renvoie `data 52e` (mauvais mot de passe) et non `data 525` (utilisateur introuvable) —
  le client LDAP .NET/Windows semble le résoudre implicitement. Enseignement documenté tel
  quel : le code d'erreur seul ne suffit pas à diagnostiquer un problème de format de DN,
  ça dépend du client LDAP utilisé par l'application.

Deux bugs réels ont aussi été trouvés et corrigés pendant ces tests (voir l'historique Git) :
l'extraction du code d'erreur AD lisait le mauvais niveau d'exception (`.Message` du wrapper
PowerShell au lieu de `.InnerException.ServerErrorMessage`, qui contient le vrai détail
serveur) et `New-TestScenarioAccount.ps1` pouvait laisser un compte à moitié configuré si la
création échouait en cours de route.

## 🔐 Sécurité & précautions

- `System.DirectoryServices.Protocols` plutôt que le module `ActiveDirectory` pour
  `Test-LdapBind.ps1` — on simule ici un client applicatif qui s'authentifie, pas un outil
  d'administration ; `New-TestScenarioAccount.ps1`, lui, utilise le module `ActiveDirectory`
  puisqu'il doit réellement créer/configurer un compte (même choix que IAM-JML-Lifecycle).
- Mot de passe toujours saisi via `SecureString` (`Read-Host -AsSecureString`), jamais en
  argument de ligne de commande en clair.
- Les comptes de test sont créés dans `OU=Utilisateurs-Test` — jamais sur un compte réel,
  jamais sur les comptes utilisés par les autres repos du portfolio.
- Le scénario `Locked` déclenche un vrai verrouillage AD (5 échecs, conforme à la politique du
  domaine) plutôt que de le simuler — se déverrouille automatiquement après 30 minutes ou via
  `Unlock-ADAccount`.
- Le scénario `ExpiredPassword` force `pwdLastSet=0` plutôt que d'attendre une expiration
  naturelle à 60 jours — raccourci assumé et documenté, pas un contournement caché.
- **Fichiers `.ps1` en UTF-8 avec BOM** dès leur création, comme le reste du portfolio —
  Windows PowerShell 5.1 lit mal les accents sans ce marqueur en tête de fichier.
