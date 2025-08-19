while ($true) {
    ############### OUVERTURE BOUCLE
 
 
    #instruction 1 : lecture et stockage de variable 
    $maVar = Read-Host  " 1- Config OU  `n 2-Config USER `n 3- Config Groupe `n 4- Gestion des ACL `n 5- Application de GPO à une OU `n 6- Outils d'Administration Avancés `n 7- Diagnostic `n 8- Quitter"
 
    if ($maVar -eq 1) {
        ############ OUVERTURE CONDITION 1
 
        $choix_ou = 0
 
        while ($choix_ou -ne 1 -and $choix_ou -ne 2) {
            Write-host "#####################################################"
            Write-host "######             OPTION CONFIG OU            ######"
            Write-host "#####################################################"
            $choix_ou = Read-Host "1 - Ajout d'OU || 2- Suppression d'OU"
 
            if ($choix_ou -eq 1) {
                $nom_ou = Read-Host "Entre le nom de l'OU a ajouter"
                New-ADOrganizationalUnit -Name "${nom_ou}" -Path "DC=sete,DC=local"
 
            }
 
            elseif ($choix_ou -eq 2) {
                $nom_ou = Read-Host "Entre le nom de l'OU a supprimer"
                Set-ADOrganizationalUnit -Identity "OU=${nom_ou},DC=sete,DC=local" -ProtectedFromAccidentalDeletion $false
                Remove-ADOrganizationalUnit -Identity "OU=${nom_ou},DC=sete,DC=local "
            }
 
            else {
 
                Write-Host "Erreur de tappe : recommencez"
            }
        }
 
 
    }##########FERMETURE CONDITION 1
 
 
    elseif ($maVar -eq 2) {
        ############################################################################################################ OUVERTURE CONDITION 2
 
        $choix_user = 0
 
        while ($choix_user -ne 1 -and $choix_user -ne 2 -and $choix_user -ne 3 -and $choix_user -ne 4) {
            Write-host "#####################################################"
            Write-host "######            OPTION CONFIG USER           ######"
            Write-host "#####################################################"
            $choix_user = Read-Host " 1 - Ajout d'user `n 2- Suppression d'user `n 3- Affectation d'un utilisateur à une OU `n 4- Affectation d'un utilisateur à un groupe "
 
            if ($choix_user -eq 1) {
                Write-host "#####################################################"
                Write-host "######        CONFIG USER   -  Ajout           ######"
                Write-host "#####################################################"
                $nom_user = Read-Host "Entre le nom complet de l'user a ajouter : "
                $login_user = Read-Host "Entre l'identifiant de l'user a ajouter : "
                $mdp = Read-host "entrez son mot de passe : "
                $ou = Read-Host "Entrez l'OU auquelle vous souhaitez integrer votre user : "
 
                New-ADUser -Name $nom_user -SamAccountName $login_user -UserPrincipalName "${login_user}@sete.local" -AccountPassword (ConvertTo-SecureString $mdp -AsPlainText -Force) -Enabled $true -Path "OU=${ou},DC=sete,DC=local"
            }
 
            elseif ($choix_user -eq 2) {
                Write-host "#####################################################"
                Write-host "######       CONFIG USER   -  Suppression      ######"
                Write-host "#####################################################"

                # Suppression par l'ID de connexion
                $login_user = Read-Host "Entre le SamAccountName de l'user a supprimer"
                Remove-ADUser -Identity $login_user
                Write-Host "Suppression réussie"
            }
 
            elseif ($choix_user -eq 3) {
                Write-host "#####################################################"
                Write-host "######     CONFIG USER   -  Affectation OU     ######"
                Write-host "#####################################################"
                Write-host ""
                Write-host "Liste des USERS"
                Write-host "________________"
                Write-host ""
                #Affiche la liste des SamAccountName des utilisateurs
                Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
                Write-host "________________"
                Write-host ""
                $login_user = Read-Host "Entre le SamAccountName de l'user a modifier"
                Write-host ""
                Write-host "Liste des OU"
                Write-host "________________"
                Write-host ""
                #Affiche la liste des noms des OU
                Get-ADOrganizationalUnit -Filter * | Select-Object Name

                Write-host "________________"
                Write-host ""

                $OU = Read-Host "Entrez l'OU dans laquelle l'affecter"   
                                               
                                                       
                # Extraction du Distinguished Name à partir de l'ID de connexion
                $dist_name = (Get-ADUser -Identity "${login_user}").DistinguishedName

                # Déplacement de l'utilisateur dans l'OU cible
                Move-ADObject -Identity $dist_name -TargetPath "OU=${OU},DC=sete,DC=local"
                Write-Host "Affectation réussie"
            }
 
            elseif ($choix_user -eq 4) {
                Write-host "#####################################################"
                Write-host "######  CONFIG USER   -  Affectation groupe    ######"
                Write-host "#####################################################"                                     
                         
                $login_user = Read-Host "Entrez le SamAccountName de l'user a modifier"
                                                                                        
                $group_name = Read-Host "Dans quel groupe voulez-vous l'affecter?"
                # Extraction du Distinguished Name vers une variable
                $dist_group = (Get-ADGroup -Identity "${group_name}").DistinguishedName
                # Ajout du membre via son SamAccountName dans le groupe via le DN
                Add-ADGroupMember -Identity $dist_group -Members $login_user

            }
 
            else {
 
                Write-Host "Erreur de frappe : recommencez"
            }
        }
 
 
    } ###########################################################################################################################################FERMETURE CONDITION 2
 
 
    elseif ($maVar -eq 3) {
        ############ OUVERTURE CONDITION 3

        $choix_groupe = 0
        while ($choix_groupe -ne 1 -and $choix_groupe -ne 2 -and $choix_groupe -ne 3) {
            
            Write-host "#####################################################"
            Write-host "######            OPTION CONFIG GROUPE           ######"
            Write-host "#####################################################"
            $choix_groupe = Read-Host " 1- Ajout de groupe `n 2- Suppression de groupe `n 3- Modification de groupe "

            if ($choix_groupe -eq 1) {
                Write-host "#####################################################"
                Write-host "######  CONFIG GROUPE   -  Création groupe    ######"
                Write-host "#####################################################"
                Write-host ""

                $groupname = Read-Host "Quel est le nom du groupe?"

                $GS = Read-Host "Quelle est l'étendue du groupe? `n 1- Local `n 2- Global `n 3- Universel?"
        
                if ($GS -eq 1) {
                    $groupscope = "DomainLocal"
                }
                elseif ($GS -eq 2) {
                    $groupscope = "Global"
                }
                elseif ($GS -eq 3) {
                    $groupscope = "Universal"
                }
                else {
                    Write-Host "Erreur"
                }


                New-ADGroup `
                    -Name $groupname `
                    -GroupScope $groupscope `
                    -Path "OU=Groupes,DC=sete,DC=local" `

                Write-Host "Groupe créé avec succès"
            }

                

            elseif ($choix_groupe -eq 2) {

                Write-host "#####################################################"
                Write-host "######  CONFIG GROUPE   -  Suppression groupe    ######"
                Write-host "#####################################################"
                Write-host ""

                $groupname = Read-Host "Quel est le nom du groupe à supprimer ?"
                Remove-ADGroup -Identity $groupname -Confirm:$false
                Write-Host "Groupe supprimé avec succès"

            }

            elseif ($choix_groupe -eq 3) {

                $opt_groupe = 0

                while ($opt_groupe -ne 1 -and $opt_groupe -ne 2) {
                
                    Write-host "#####################################################"
                    Write-host "######    MODIF GROUPE    -  Choix des Options    ######"
                    Write-host "#####################################################"
                    $opt_groupe = Read-Host " 1- Modifier le nom du groupe `n 2- Modifier l'étendue du groupe"
                    
                    if ($opt_groupe -eq 1) {

                        $ancien_groupname = Read-Host "Quel est le nom du groupe dont vous voulez changer le nom?"
                        $nouveau_groupname = Read-Host "Quel est son nouveau nom?"

                        Rename-ADObject -Identity "CN=$ancien_groupname,OU=Groupes,DC=sete,DC=local" -NewName $nouveau_groupname

                        Write-Host "Nom du groupe modifié avec succès"
                    }

                    elseif ($opt_groupe -eq 2) {
                    
                        $groupname = Read-Host "Quel est le nom du groupe dont vous voulez changer l'étendue?"
                        $GS = Read-Host "Quelle est la nouvelle étendue du groupe? 1- Local `n 2- Global `n 3- Universelle?"
        
                        if ($GS -eq 1) {
                            $groupscope = "DomainLocal"
                        }
                        elseif ($GS -eq 2) {
                            $groupscope = "Global"
                        }
                        elseif ($GS -eq 3) {
                            $groupscope = "Universal"
                        }
                        else {
                            Write-Host "Erreur"
                        }

                        Set-ADGroup -Identity $groupname -GroupScope $groupscope

                        Write-Host "Étendue du groupe modifiée avec succès"

                    
                    }
                    
                }

            }
            else {
                Write-Host "Erreur"
            }    
        }
    } ##########FERMETURE CONDITION 3
 
 
    elseif ($maVar -eq 4) {
        ############ OUVERTURE CONDITION 4
 
        Write-host "#####################################################"
        Write-host "######                              CONFIG USER   -  Gestion ACL                                ######"
        Write-host "#####################################################`n"
        Write-Host " Rappel des principaux types de permissions (FileSystemRights) disponibles :`n"
        Write-Host "`t* FullControl`t: Contrôle total (toutes les permissions)"
        Write-Host "`t* Modify`t: Lire, écrire, supprimer, créer, modifier"
        Write-Host "`t* ReadAndExecute`t: Lire le contenu et exécuter les fichiers"
        Write-Host "`t* Read`t: Lire les fichiers et les attributs"
        Write-Host "`t* Write`t: Écrire dans les fichiers, créer des fichiers/dossiers"
        Write-Host "`t* ListDirectory`t: Voir le contenu du dossier"
        Write-Host "`t* ReadAttributes`t: Lire les attributs des fichiers/dossiers"
        Write-Host "`t* ReadExtendedAttributes`t: Lire les attributs étendus (métadonnées)"
        Write-Host "`t* WriteAttributes`t: Modifier les attributs"
        Write-Host "`t* WriteExtendedAttributes`t: Modifier les attributs étendus"
        Write-Host "`t* CreateFiles`t: Créer des fichiers dans un dossier"
        Write-Host "`t* CreateDirectories`t: Créer des sous-dossiers"
        Write-Host "`t* DeleteSubdirectoriesAndFiles`t: Supprimer les fichiers et sous-dossiers"
        Write-Host "`t* Delete`t: Supprimer le fichier ou le dossier"
        Write-Host "`t* ReadPermissions`t: Lire les permissions définies sur l’objet"
        Write-Host "`t* ChangePermissions`t: Modifier les ACL"
        Write-Host "`t* TakeOwnership`t: Prendre possession de l’objet"
        Write-Host "`t* Synchronize`t: Synchroniser l’accès aux fichiers (usage système)"
        Write-host "#####################################################`n"
        # Chemin du dossier auquel on veut attribuer des droits
        $folderPath = Read-host "Entrez le chemin de la ressource concernée. exemple C:\Partage\Docs"
 
        # Nom d'utilisateur avec domaine (ou juste le nom si utilisateur local)
        $user = Read-Host "Entrez l'identité de l'utilisateur concerné"
 
        $permission = Read-Host "Entrez la permission"
 
        # Récupère les règles de contrôle d’accès (ACL) actuelles du dossier
        $acl = Get-Acl $folderPath
 
        # Crée une règle d’accès :
        # Paramètres :
        # - $user : l’utilisateur ou groupe à qui on attribue les droits
        # - "FullControl" : type d’autorisation (peut être Read, Write, Modify, etc.)
        # - "ContainerInherit,ObjectInherit" :
        #     ContainerInherit = s'applique aux sous-dossiers
        #     ObjectInherit    = s'applique aux fichiers contenus dans le dossier
        # - "None" : signifie que l’héritage des permissions n’est pas bloqué
        # - "Allow" : on autorise l'accès (au lieu de "Deny" pour interdire)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "SETE\$user",                          # Nom de l’utilisateur ou groupe
            $permission,                 # Type de permission
            "ContainerInherit,ObjectInherit", # Application récursive sur sous-dossiers/fichiers
            "None",                        # Pas de restriction d’héritage
            "Allow"                        # Type d’accès : autoriser
        )
 
        # Ajoute la règle au jeu d’ACL actuel
        $acl.SetAccessRule($rule)
 
        # Applique les nouvelles permissions au dossier
        Set-Acl -Path $folderPath -AclObject $acl
 
                            
                         
 
 
 
    } ##########FERMETURE CONDITION 4


    elseif ($mavar -eq 5) {
        ############ OUVERTURE CONDITION 5
 
        Write-Host "##############################################"
        Write-Host "######   Application de GPO sur une OU   ######"
        Write-Host "##############################################"

        $nom_ou = Read-Host "Entre le nom de l'OU a ajouter"
        New-ADOrganizationalUnit -Name "${nom_ou}" -Path "DC=sete,DC=local"
        $gpoName = "GPO_Securite_$nom_ou"
        New-GPO -Name $gpoName

        # Liste des paramètres à appliquer
        $gpos = @(

            # Désactiver les ports USB
            @{ Key = "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR"; Name = "Start"; Type = "DWord"; Value = 4 },

            # Mot de passe requis
            @{ Key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LimitBlankPasswordUse"; Type = "DWord"; Value = 1 },

            # Bloquer le panneau de config
            @{ Key = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoControlPanel"; Type = "DWord"; Value = 1 },

            # Bloquer le gestionnaire de tâches
            @{ Key = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableTaskMgr"; Type = "DWord"; Value = 1 },

            # Interdire l'installation auto des périphériques
            @{ Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"; Name = "DenyUnspecified"; Type = "DWord"; Value = 1 }
        )

        # Appliquer chaque paramètre à la GPO
        foreach ($gpo in $gpos) {
            Set-GPRegistryValue -Name $gpoName -Key $gpo.Key -ValueName $gpo.Name -Type $gpo.Type -Value $gpo.Value
        }

        # Lier la GPO à l’OU
        $resultat_gpo = New-GPLink -Name $gpoName -Target "OU=$nom_ou,DC=sete,DC=local"
        if ($resultat_gpo) {
            Write-Host "La GPO '$gpoName' a été créée, configurée et liée à l'OU '$nom_ou'."
        }
        else {
            Write-Host "Erreur! La GPO '$gpoName' n'a pas été liée à l'OU "
        }
    } ##########FERMETURE CONDITION 5

    elseif ($mavar -eq 6) {
        ########### OUVERTURE CONDITION 6
    
        $opt_admin = 0

        while ($opt_admin -ne 1 -and $opt_admin -ne 2 -and $opt_admin -ne 3) {
        
            Write-Host "###########################################"
            Write-Host "###### OUTILS ADMINISTRATION AVANCÉE ######"
            Write-Host "###########################################"

            $opt_admin = Read-Host " 1- Surveillance des évènements `n 2- Gestion des processus `n 3- Configuration de sécurité avancée"

            if ($opt_admin -eq 1) {
                # Surveillance des événements système
                $event_log = Read-Host "Nom du journal"
                $event_id = Read-Host "ID d'événement à surveiller"
                Get-WinEvent -LogName $event_log | Where-Object { $_.Id -eq $event_id } | Select-Object TimeCreated, Id, Message
            }

            elseif ($opt_admin -eq 2) {
                # Gestion des processus sur un ordinateur distant
                $remote_computer = Read-Host "Nom du poste distant"
                $process_name = Read-Host "Nom du processus à surveiller"
                Get-Process -ComputerName $remote_computer -Name $process_name
            }

            elseif ($opt_admin -eq 3) {
                # --- Désactivation du partage de fichiers et imprimantes ---
                $key = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                Set-ItemProperty -Path $key -Name "NoSharing" -Value 1
                Write-Host "Le partage de fichiers et d'imprimantes a été désactivé."
            }

            else {
                Write-Host "Choix invalide."
            }

        }
                   
    } ##########FERMETURE CONDITION 6

    elseif ($mavar -eq 7) {
        ########### OUVERTURE CONDITION 7
        $LogPath = "C:\DIAG"
        $Rapport = "$LogPath\rapport_diagnostic.txt"
        $confirm_diag = Read-Host "`n Voulez-vous lancer l'outil de diagnostic automatique ? `n (Dans $Rapport) `n `n 1 - OUI `n 2 - NON `n"

        # MISE EN PLACE DU CHEMIN ET FICHIER DE STOCKAGE DES LOGS


        if (-not (Test-Path $logPath)) {
            # Si $LogPath renvoi une valeur False
            New-Item -Path $logPath -ItemType Directory # Alors un nouveau dossier est créé selon le chemin dans $LogPath
        }                                               # Pas de sinon, inutile dans ce cas


        "########################################################################`n############### RAPPORT DIAGNOSTIC - $(Get-Date) ###############`n########################################################################`n" | Out-File $Rapport # Envoi le résultat de ce qui se trouve avant le pipe vers le fichier selon le chemin dans $Rapport
 



        # ÉVÉNEMENTS SYSTÈME CRITIQUES ET D'ERREURS DU JOUR DEPUIS MINUIT
 
        Add-Content $Rapport "`n#################################################`n##### DERNIERS ÉVÉNEMENTS D'ERREUR (System) #####`n#################################################`n"   #Ajoute du contenu au fichier selon le chemin dans $Rapport
        $evenements = Get-WinEvent -FilterHashtable @{  # Plus efficace que d'utilise un pipe avec Where-Object, depuis l'arrivée de Get-WinEvent qui remplace Get-EventLog, d'après learn.microsoft
            LogName   = 'System'
            StartTime = (Get-Date).Date                 # Pour selectionner seulement les events du jour
        } | Where-Object { # Je n'ai pas réussi autrement qu'avec Where-Object
            $_.Level -in 1, 2, 3                           # Je veux seulement les events Critiques et d'Erreurs, sinon il fallait que je fasse un jeu d'instruction pour chaque, pour mes tests j'ai rajouté 3 pour afficher les avertissements
        }                                           

        foreach ($event in $evenements) {
            Add-Content $Rapport "ID: $($event.Id) - $($event.TimeCreated) - $($event.Message)" # Pour chaque objets du tableau $evenements je veux l'ID, La date de création de l'event et le message associé
        }


        # PROCESSUS UTILISANT BEAUCOUP DE MÉMOIRE

        $LimiteMemoire = 90                                                        # J'ai pris 90Mo pour pouvoir faire mes tests avec 3-4 lignes maxi, sinon j'ai vu que 500Mo était préconisé

        Add-Content $Rapport "`n#############################`n##### PROCESSUS > $LimiteMemoire Mo #####`n#############################`n"

        $processus = Get-Process | Where-Object { # Je stocke dans ma variable la liste des processus ayant une quantité de mémoire phisique supérieure à 500Mo
            $_.WorkingSet64 -gt ($LimiteMemoire * 1MB) # 1MB sert à définir la valeur $LimiteMemoire comme étant en Mo
        } 

        if ($processus) {
            # Si $processus renvoi une valeur True
            $processus | Sort-Object WorkingSet64 -Descending | ForEach-Object { # Tri les objets de manière décroissante sur la charge mémoire
                $mo = ($_.WorkingSet64 / 1MB)                      # 
                Add-Content $Rapport "$($_.ProcessName) - ${mo} Mo"                # J'ajoute dans $Rapport le nom du processus et sa charge mémoire
            }
        }
        else {
            Add-Content $Rapport "Aucun processus au-dessus de $LimiteMemoire Mo"  # Si aucun processus ne dépasse la limite, ajoute le message au $Rapport
        }


        # SERVICES ARRÊTÉS MAIS CONFIGURÉS EN AUTOMATIQUE

        Add-Content $Rapport "`n#################################################`n##### SERVICES EN ÉCHEC (Auto mais arrêtés) #####`n#################################################`n"
        $services = Get-CimInstance -ClassName Win32_Service | Where-Object { # Pour intérroger la classe WMI (à approfondir) Win32_Service qui permet d'accéder aux propriété et à l'état d'un service
            $_.StartMode -eq "Auto" -and $_.State -ne "Running"                    # je cherche à extraire les objets dont la valeur sur leur démarrage au démarrage du système et sur "Auto" et dont l'état est différent de "Running"
        }

        if ($services) {
            # Si $services renvoi une valeur True
            $services | ForEach-Object {
                Add-Content $Rapport "$($_.ProcessId) - $($_.Name) - $($_.DisplayName) - $($_.State)"      #Alors envoi le processID, le nom systeme, le nom complet et l'état vers le fichier de diagnostic
            }
        }
        else {
            Add-Content $Rapport "Aucun service critique arrêté"
        }

        # FIN DU RAPPORT
        Add-Content $Rapport "`n##########################`n##### FIN DU RAPPORT #####`n##########################`n"
                     

        Write-Host "`n`n Rapport enregistré dans $Rapport `n`n"


            
    } ##########FERMETURE CONDITION 7

    elseif ($mavar -eq 8) {
        ########### OUVERTURE CONDITION 8
    
        break
            
    } ##########FERMETURE CONDITION 8

    else {
        ############ OUVERTURE CONDITION finale
 
        Write-Host "Erreur de lecture"
 
 
    } ##########FERMETURE CONDITION finale
 
 
}################# FERMETURE BOUCLE