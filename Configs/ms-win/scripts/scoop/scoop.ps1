<#
.SYNOPSIS
    Script to install and configure Scoop with the @gm64x user intents.
.DESCRIPTION
    Verifies conditions, installs Scoop if missing, cleans duplicate sfsu hooks
    from the PowerShell profile, and installs/configures necessary packages
    (git, 7zip, tlrc, sfsu, extras bucket) only if they are not already installed.
#>

function Test-IsElevated {
    # Verifica se o script está rodando com privilégios de Administrador
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Test-IsWindows {
    # Verifica se o sistema operacional é Windows
    return $env:OS -eq "Windows_NT"
}

function verifyConditions {
    # Garante que o script não rode como Administrador e que o SO seja Windows
    if (Test-IsElevated) {
        Write-Error "This script must not run as an administrator."
        return $false
    }
    if (-not (Test-IsWindows)) {
        Write-Error "This script is not compatible with non-Windows systems."
        return $false
    }
    return $true
}

function installScoop {
    # Checa se o comando 'scoop' existe antes de tentar instalar
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Host "Scoop is already installed."
        return
    }
    Write-Host "Scoop is not installed. Installing..."
    # Instala o Scoop
    Invoke-Expression (Invoke-RestMethod -Uri 'https://get.scoop.sh')
}

function Cleanup-ProfileHooks {
    Write-Host "--- Limpando Hooks duplicados no $profile ---"
    $profilePath = $profile
    $hookLine = "Invoke-Expression (&sfsu hook)"
    $oldScoopSearchHook = "<#. ([ScriptBlock]::Create((& scoop-search --hook | Out-String))) #>"

    # Se o arquivo de perfil não existir, cria um vazio
    if (-not (Test-Path $profilePath)) {
        New-Item -Path $profilePath -ItemType File -Force | Out-Null
        Write-Host "Profile file did not exist. Created new file."
        return
    }

    # 1. Lê o conteúdo atual linha por linha
    $content = Get-Content -Path $profilePath -ErrorAction Stop

    # 2. Filtra o conteúdo, mantendo APENAS a primeira ocorrência do hook, ou todas as outras linhas
    $foundHook = $false
    $newContent = @()

    foreach ($line in $content) {
        # Remove any line that matches the old scoop-search hook
        if ($line -eq $oldScoopSearchHook) {
            Write-Host "Removed old scoop-search hook from profile."
            continue
        }
        # Usamos -like para uma correspondência simples e flexível
        if ($line -like "*$hookLine*") {
            if (-not $foundHook) {
                # Mantém a primeira ocorrência
                $newContent += $line
                $foundHook = $true
            }
            # Ignora ocorrências subsequentes (REMOVE AS DUPLICADAS)
        } else {
            # Mantém todas as outras linhas
            $newContent += $line
        }
    }

    # 3. Reescreve o arquivo de perfil apenas se houver uma alteração (incluindo a remoção de duplicatas ou do hook antigo)
    if ($newContent.Count -ne $content.Count) {
        Write-Host "Removed duplicate sfsu hook lines and/or old scoop-search hook, updated profile."
        $newContent | Set-Content -Path $profilePath -Force
    } else {
        Write-Host "sfsu hook already present and no duplicates or old scoop-search hook found."
    }
}


function prepareScoop {

    # Função auxiliar para verificar a instalação do Scoop (pacotes)
    function Test-ScoopPackageInstalled {
        param([Parameter(Mandatory=$true)]$Name)
        # Checks if the package name appears in the output of 'scoop list'
        return (scoop list | Select-String -Pattern "^\s*$Name\s" -Quiet)
    }

    # Função auxiliar para verificar se o bucket está adicionado
    function Test-ScoopBucketAdded {
        param([Parameter(Mandatory=$true)]$Name)
        # Skip the header, split each line, and check the first column for the bucket name
        $buckets = scoop bucket list | Select-Object -Skip 1
        foreach ($line in $buckets) {
            $cols = $line -split '\s+'
            if ($cols[0] -eq $Name) { return $true }
        }
        return $false
    }

    Write-Host "`n--- Verificando e Instalando Pacotes Necessários ---"

    # 1. Instalar git e 7zip

    if (-not (Test-ScoopPackageInstalled "git")) {
        Write-Host "Scoop installing git..."
        scoop install git
    } else {
        Write-Host "git is already installed via Scoop (skipping install)."
    }

    if (-not (Test-ScoopPackageInstalled "7zip")) {
        Write-Host "Scoop installing 7zip..."
        scoop install 7zip
    } else {
        Write-Host "7zip is already installed via Scoop (skipping install)."
    }

    # 2. Adicionar o bucket 'extras'

    if (-not (Test-ScoopBucketAdded "extras")) {
        Write-Host "Scoop adding bucket extras..."
        scoop bucket add extras
    } else {
        Write-Host "Bucket 'extras' is already added (skipping addition)."
    }

    # 3. Instalar tlrc

    if (-not (Test-ScoopPackageInstalled "tlrc")) {
        Write-Host "Scoop installing tlrc..."
        scoop install tlrc
    } else {
        Write-Host "tlrc is already installed via Scoop (skipping install)."
    }

    # 4. Instalar sfsu

    $hookLine = "Invoke-Expression (&sfsu hook)"
    $sfsuInstalled = Test-ScoopPackageInstalled "sfsu"

    if (-not $sfsuInstalled) {
        Write-Host "Scoop installing sfsu..."
        scoop install sfsu
    } else {
        Write-Host "sfsu is already installed via Scoop (skipping install)."
    }

    # 5. Configurar Hook do sfsu

    # Checa se a linha de hook JÁ ESTÁ presente no $profile (após a limpeza e instalação)
    if (-not (Get-Content -Path $profile -ErrorAction SilentlyContinue | Select-String -Pattern ([regex]::Escape($hookLine)) -Quiet)) {
        Write-Host "Adding sfsu hook to $profile..."
        Add-Content -Path $profile -Value "`n$hookLine"
    } else {
        Write-Host "sfsu hook is already present in $profile (skipping addition)."
    }

    Write-Host "--- Verificação de Pacotes Concluída ---"
}


# --- Execução Principal ---

# 1. Verifica as condições e instala o Scoop
if (verifyConditions) {
    installScoop

    # 2. Limpa o perfil antes de instalar ou verificar qualquer coisa
    Cleanup-ProfileHooks

    # 3. Instala pacotes e adiciona o hook de forma controlada
    prepareScoop
}
