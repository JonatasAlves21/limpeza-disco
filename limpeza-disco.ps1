#Requires -Version 5.1
<#
    ============================================================
     LIMPEZA DE ARMAZENAMENTO / DISCO CHEIO  -  v2
     Autor: Jonatas Alves  -  Licenca MIT
    ============================================================

     NAO toca em agentes de seguranca e gestao (antivirus, DLP, MDM).
     NAO apaga documentos do usuario. Apaga cache/temp, residuo de
     atualizacao e desidrata pastas de nuvem (arquivos continuam no
     SharePoint).

     ORDEM DE GANHO REAL - observada em campo:
       1) C:\Windows.old ............................ 20-60 GB
       2) Desidratar biblioteca SharePoint .......... 10-52 GB
       3) OST do Outlook (reduzir janela offline) ... 10-30 GB
       4) Limpeza de Disco / Windows Update ......... 4-20 GB
       5) Temp / lixeira / caches ................... 1-6 GB

     O QUE MUDOU DA v1 (motivo de cada mudanca):
       - Log em UTF-8 por um unico escritor. Na v1 o Tee-Object gravava
         UTF-16 e os echo do cmd gravavam OEM: o arquivo saia ilegivel.
       - Varredura unica. A v1 varria C:\Users na etapa 2 e de novo na
         etapa 3. Agora e uma passada, agregada em varias profundidades.
       - Caminhada com System.IO em vez de Get-ChildItem -Recurse, e sem
         entrar em junction. A v1 contava C:\Users\All Users ->
         C:\ProgramData duas vezes e varria o mesmo GB duas vezes.
       - DISM /ResetBase em background (era 5-15 min bloqueando).
       - Windows.old removido por takeown+rd, nao pelo cleanmgr grafico
         (na pratica ninguem marcava a caixa e ficavam 51 GB no disco).
       - Atributo de nuvem corrigido: RECALL_ON_DATA_ACCESS (0x400000),
         nao so OFFLINE (0x1000).
       - Ordenacao numerica e separador decimal consistente.
       - Emite resumo .json e um .html pronto para anexar no chamado.
       - Modo -Auto para execucao sem interacao (ex.: implantacao via MDM).

    PARAMETROS
      -Auto                 Nao pergunta nada. Aplica so o que e seguro
                            sem supervisao (temp, caches, WU, DISM,
                            Storage Sense). Windows.old, hibernacao,
                            lixeira de todos os perfis e desidratacao
                            ficam de fora a menos que pedidos por flag.
      -RemoveWindowsOld     Em -Auto, autoriza remover C:\Windows.old.
      -DisableHibernation   Em -Auto, autoriza powercfg /h off.
      -EmptyAllRecycleBins  Em -Auto, autoriza esvaziar lixeira de todos.
      -CloudPath <caminho>  Pasta OneDrive/SharePoint a desidratar.
      -NoDism               Nao roda DISM /StartComponentCleanup.
      -OutDir <caminho>     Onde gravar relatorio/log.
#>

[CmdletBinding()]
param(
    [switch]$Auto,
    [switch]$RemoveWindowsOld,
    [switch]$DisableHibernation,
    [switch]$EmptyAllRecycleBins,
    [switch]$NoDism,
    [string]$CloudPath,
    [string]$OutDir
)

# ------------------------------------------------------------------
#  Auto-elevacao (feita aqui, e nao no .bat, porque o PowerShell
#  monta a linha de comando com as aspas certas para caminhos com
#  espaco - o Start-Process do .bat da v1 quebrava nesses casos)
# ------------------------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin  = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host 'Solicitando privilegios de administrador...'
    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { $argLine += ' -' + $kv.Key }
        } else {
            $argLine += ' -{0} "{1}"' -f $kv.Key, $kv.Value
        }
    }
    try {
        Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $argLine -Verb RunAs
    } catch {
        Write-Host 'Elevacao cancelada. Rode como Administrador.' -ForegroundColor Red
    }
    return
}

$ErrorActionPreference = 'Continue'
# Barras de progresso do Remove-Item/Get-ChildItem custam tempo real
# em arvore grande. Desligar e um dos ganhos baratos desta versao.
$ProgressPreference    = 'SilentlyContinue'

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch { }

# ------------------------------------------------------------------
#  Constantes
# ------------------------------------------------------------------
# FILE_ATTRIBUTE_OFFLINE 0x1000 | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS 0x400000
# A v1 testava so 0x1000, entao pasta ja desidratada aparecia como se
# estivesse inteira no disco.
$script:CLOUD_ONLY = 0x401000
# SID do grupo Administradores. Usar o SID e nao o nome porque em
# Windows pt-BR o grupo chama "Administradores" e o icacls falha.
$script:ADMINS_SID = '*S-1-5-32-544'

$script:Applied  = New-Object System.Collections.ArrayList
$script:Skipped  = New-Object System.Collections.ArrayList
$script:Pending  = New-Object System.Collections.ArrayList
$script:Timings  = New-Object System.Collections.ArrayList
$script:Findings = New-Object System.Collections.ArrayList

# ------------------------------------------------------------------
#  Saida / log
# ------------------------------------------------------------------
if (-not $OutDir) {
    if ($Auto) {
        $OutDir = 'C:\ProgramData\LimpezaDisco'
    } else {
        $OutDir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Relatorio_Limpeza_Disco'
    }
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$script:Utf8    = New-Object System.Text.UTF8Encoding($false)
$script:LogPath = Join-Path $OutDir 'log_limpeza.txt'
[IO.File]::WriteAllText($script:LogPath, '', $script:Utf8)

function Write-Log {
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0)][AllowEmptyString()][string]$Text = '',
        [switch]$Silent
    )
    process {
        if (-not $Silent) { Write-Host $Text }
        [IO.File]::AppendAllText($script:LogPath, ($Text + "`r`n"), $script:Utf8)
    }
}

function Write-Head {
    param([string]$Text)
    Write-Log ''
    Write-Log ('=' * 66)
    Write-Log ('   ' + $Text)
    Write-Log ('=' * 66)
}

function Confirm-Step {
    param([string]$Question, [bool]$AutoAnswer = $false)
    if ($Auto) {
        Write-Log ('   [AUTO] {0} -> {1}' -f $Question, $(if ($AutoAnswer) { 'S' } else { 'N' }))
        return $AutoAnswer
    }
    while ($true) {
        $r = Read-Host "   $Question [S/N]"
        if ($r -match '^\s*[SsYy]') { return $true }
        if ($r -match '^\s*[Nn]')   { return $false }
    }
}

function Wait-Enter {
    param([string]$Text = 'Enter para continuar')
    if (-not $Auto) { Read-Host "   $Text" | Out-Null }
}

# Formata sempre pelo operador -f, para o separador decimal nao alternar
# entre virgula e ponto no mesmo relatorio (bug cosmetico da v1).
function Format-GB { param([double]$Bytes) '{0:N2}' -f ($Bytes / 1GB) }

function Get-DriveC {
    $d = New-Object System.IO.DriveInfo 'C:\'
    [pscustomobject]@{ Free = [double]$d.AvailableFreeSpace; Total = [double]$d.TotalSize }
}

function Start-Step {
    param([string]$Name)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    [pscustomobject]@{ Name = $Name; Watch = $sw }
}

function Stop-Step {
    param($Step)
    $Step.Watch.Stop()
    [void]$script:Timings.Add([pscustomobject]@{
        Etapa    = $Step.Name
        Segundos = [math]::Round($Step.Watch.Elapsed.TotalSeconds, 1)
    })
    Write-Log ('   (etapa em {0:N1}s)' -f $Step.Watch.Elapsed.TotalSeconds)
}

# ------------------------------------------------------------------
#  Nucleo da medicao
#
#  Caminhada iterativa com System.IO.DirectoryInfo.Enumerate*:
#    - nao entra em junction/symlink  -> C:\Users\All Users nao e mais
#      contado (nem varrido) como se fosse parte de C:\Users
#    - try/catch por diretorio        -> Access Denied nao aborta o ramo
#    - FileInfo vem com atributo em cache da enumeracao, sem syscall
#      extra por arquivo (a diferenca contra Get-ChildItem -Recurse)
#    - KeyDepth: em quantos niveis abaixo de $Root agregar
# ------------------------------------------------------------------
function Measure-Tree {
    param([string]$Root, [int]$KeyDepth = 0)

    $agg = @{}
    if (-not (Test-Path -LiteralPath $Root)) { return $agg }

    $rootDi = $null
    try { $rootDi = New-Object System.IO.DirectoryInfo $Root } catch { return $agg }
    $base = $rootDi.FullName.TrimEnd('\')

    # A chave de agregacao e propagada na descida, junto com a profundidade.
    # Nao derivar a chave por Substring do caminho: se $Root chegar num
    # formato diferente do que a enumeracao devolve (8.3, casing, barra
    # final), o corte cai no meio do caminho e a chave sai corrompida.
    $stack = New-Object System.Collections.Stack
    $stack.Push([pscustomobject]@{ Path = $base; Depth = 0; Key = $base })

    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $di   = $null
        try { $di = New-Object System.IO.DirectoryInfo $item.Path } catch { continue }

        if (-not $agg.ContainsKey($item.Key)) {
            $agg[$item.Key] = [pscustomobject]@{ Path = $item.Key; Tot = [double]0; Loc = [double]0; Files = 0 }
        }
        $node = $agg[$item.Key]

        try {
            foreach ($sub in $di.EnumerateDirectories()) {
                if ($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                $childDepth = $item.Depth + 1
                if ($childDepth -le $KeyDepth) { $childKey = $sub.FullName.TrimEnd('\') }
                else                           { $childKey = $item.Key }
                $stack.Push([pscustomobject]@{ Path = $sub.FullName; Depth = $childDepth; Key = $childKey })
            }
        } catch { }

        try {
            foreach ($f in $di.EnumerateFiles()) {
                $len = $f.Length
                $node.Tot += $len
                if (-not ($f.Attributes -band $script:CLOUD_ONLY)) { $node.Loc += $len }
                $node.Files++
            }
        } catch { }
    }
    return $agg
}

# Re-agrega um resultado de Measure-Tree numa profundidade menor,
# em vez de varrer o disco de novo.
function Get-Rollup {
    param([hashtable]$Agg, [string]$Root, [int]$Depth)
    # Conta componentes em vez de fatiar string, pelo mesmo motivo do
    # Measure-Tree: imune a divergencia de prefixo entre $Root e as chaves.
    $baseCount = ($Root.TrimEnd('\') -split '\\').Count
    $out       = @{}
    foreach ($v in $Agg.Values) {
        $parts = $v.Path -split '\\'
        $take  = [Math]::Min($baseCount + [Math]::Max($Depth, 0), $parts.Count)
        $key   = ($parts[0..($take - 1)]) -join '\'
        if (-not $out.ContainsKey($key)) {
            $out[$key] = [pscustomobject]@{ Path = $key; Tot = [double]0; Loc = [double]0; Files = 0 }
        }
        $out[$key].Tot   += $v.Tot
        $out[$key].Loc   += $v.Loc
        $out[$key].Files += $v.Files
    }
    return $out
}

# Apaga o CONTEUDO de uma pasta, preservando a pasta.
# Caminho rapido em .NET; se algum arquivo estiver em uso, cai no
# Remove-Item daquele ramo para nao perder o resto (Directory.Delete
# recursivo aborta inteiro no primeiro arquivo travado).
function Clear-FolderContent {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        foreach ($d in [System.IO.Directory]::EnumerateDirectories($Path)) {
            try { [System.IO.Directory]::Delete($d, $true) }
            catch { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
        }
    } catch { }
    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($Path)) {
            try { [System.IO.File]::Delete($f) } catch { }
        }
    } catch { }
}

function Remove-ProtectedTree {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    & takeown.exe /F $Path /R /A /D S           2>&1 | Out-Null
    & icacls.exe  $Path /grant "$($script:ADMINS_SID):(F)" /T /C 2>&1 | Out-Null
    & cmd.exe /c rd /s /q "$Path"               2>&1 | Out-Null
    return (-not (Test-Path -LiteralPath $Path))
}

# ------------------------------------------------------------------
#  Inicio
# ------------------------------------------------------------------
$runStart = [System.Diagnostics.Stopwatch]::StartNew()
$d0       = Get-DriveC

Write-Log ('=== LIMPEZA DE ARMAZENAMENTO v2 - {0} - {1} ===' -f `
            (Get-Date -Format 'dd/MM/yyyy HH:mm:ss'), $env:COMPUTERNAME)
Write-Log ('Operador: {0}\{1}   |   Modo: {2}' -f $env:USERDOMAIN, $env:USERNAME, `
            $(if ($Auto) { 'AUTOMATICO' } else { 'INTERATIVO' }))
Write-Log ('Relatorio: {0}' -f $OutDir)

if (-not $Auto) {
    Write-Head ('LIMPEZA DE ARMAZENAMENTO - ' + $env:COMPUTERNAME)
    Write-Log '   Nada e alterado sem confirmacao (S/N) em cada etapa.'
    Write-Log '   NAO sera tocado: antivirus, DLP, MDM e documentos do usuario.'
    Write-Log ''
    Write-Log '   FECHE Teams, Edge e Chrome antes de continuar (cache em uso'
    Write-Log '   nao e liberado com o programa aberto).'
    Wait-Enter
}

# Perfis reais de usuario (sem junction: All Users, Default User,
# Todos os Usuarios, Usuario Padrao). A v1 listava esses como se
# fossem perfis, poluindo o relatorio anexado ao chamado.
$script:Profiles = @(
    Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) }
)

# ==================================================================
#  [1/12] Espaco em disco
# ==================================================================
Write-Head 'DIAGNOSTICO (somente leitura)'
Write-Log ('[1/12] Disco C:  Total: {0} GB  |  Livre: {1} GB  ({2:N1}% livre)' -f `
            (Format-GB $d0.Total), (Format-GB $d0.Free), (($d0.Free / $d0.Total) * 100))

# ==================================================================
#  [2/12] Varredura unica: raiz do C: + perfis, uma passada
# ==================================================================
$st = Start-Step 'Varredura unica (raiz + perfis)'
Write-Log ''
Write-Log '[2/12] Varredura de espaco (uma passada, sem seguir junction)'

$usersAgg  = Measure-Tree -Root 'C:\Users' -KeyDepth 3   # C:\Users\<perfil>\<n1>\<n2>
$usersRoot = (Get-Rollup -Agg $usersAgg -Root 'C:\Users' -Depth 0)['C:\Users']

$rootRows = New-Object System.Collections.ArrayList
[void]$rootRows.Add($usersRoot)
Get-ChildItem 'C:\' -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object {
        -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and
        $_.FullName -ne 'C:\Users'
    } |
    ForEach-Object {
        $r = (Measure-Tree -Root $_.FullName -KeyDepth 0)[$_.FullName.TrimEnd('\')]
        if ($r) { [void]$rootRows.Add($r) }
    }

Write-Log ''
Write-Log '   -- Maiores pastas na raiz do C: --'
$rootRows | Sort-Object -Property Loc -Descending | Select-Object -First 14 | ForEach-Object {
    Write-Log ('   {0,9} GB   {1}' -f (Format-GB $_.Loc), $_.Path)
    [void]$script:Findings.Add([pscustomobject]@{
        Escopo = 'raiz'; Caminho = $_.Path
        GB_disco = [double]((Format-GB $_.Loc) -replace ',', '.')
        GB_total = [double]((Format-GB $_.Tot) -replace ',', '.')
    })
}

Write-Log ''
Write-Log '   -- Maiores pastas dentro dos perfis (3 niveis) --'
Write-Log '   "no disco" x "totais" difere quando a pasta e de nuvem com'
Write-Log '   Arquivos sob Demanda: o que esta so na nuvem nao ocupa disco.'
$topProfileDirs = $usersAgg.Values | Sort-Object -Property Loc -Descending | Select-Object -First 20
foreach ($row in $topProfileDirs) {
    if ($row.Loc -lt 1GB) { continue }
    Write-Log ('   {0,9} GB no disco  (de {1,9} GB totais)  {2}' -f `
                (Format-GB $row.Loc), (Format-GB $row.Tot), $row.Path)
    [void]$script:Findings.Add([pscustomobject]@{
        Escopo = 'perfil'; Caminho = $row.Path
        GB_disco = [double]((Format-GB $row.Loc) -replace ',', '.')
        GB_total = [double]((Format-GB $row.Tot) -replace ',', '.')
    })
}
Stop-Step $st

# ==================================================================
#  [3/12] Suspeitos nomeados
# ==================================================================
$st = Start-Step 'Suspeitos nomeados'
Write-Log ''
Write-Log '[3/12] Suspeitos nomeados'

# -- OST do Outlook
$ostRows = @()
foreach ($p in $script:Profiles) {
    $ostDir = Join-Path $p.FullName 'AppData\Local\Microsoft\Outlook'
    if (Test-Path -LiteralPath $ostDir) {
        $ostRows += @(Get-ChildItem -LiteralPath $ostDir -Filter '*.ost' -File -Force -ErrorAction SilentlyContinue)
    }
}
if ($ostRows.Count) {
    Write-Log '   -- OST do Outlook (cache de e-mail):'
    foreach ($o in ($ostRows | Sort-Object -Property Length -Descending)) {
        Write-Log ('      {0,8} GB  {1}' -f (Format-GB $o.Length), $o.FullName)
        if ($o.Length -gt 15GB) {
            [void]$script:Pending.Add(
                ('OST de {0} GB em {1}: reduzir "Email para manter offline" para 3 ou 6 meses ' +
                 '(Outlook > Arquivo > Configuracoes de Conta > Alterar). Precisa ser feito na ' +
                 'sessao do usuario.') -f (Format-GB $o.Length), $o.Name)
        }
    }
} else {
    Write-Log '   -- Nenhum OST encontrado.'
}

# -- Residuo de atualizacao do Windows
# 'tree'   = remover a pasta inteira (residuo puro de upgrade)
# 'clear'  = esvaziar conteudo, preservar a pasta (o Windows a recria)
# 'report' = so relatar: em alguns OEM guarda midia de recuperacao
$upgradeTargets = @(
    [pscustomobject]@{ Path = 'C:\Windows.old';      Mode = 'tree'   },
    [pscustomobject]@{ Path = 'C:\$WinREAgent';      Mode = 'tree'   },
    [pscustomobject]@{ Path = 'C:\$SysReset';        Mode = 'tree'   },
    [pscustomobject]@{ Path = 'C:\Windows\Panther';  Mode = 'clear'  },
    [pscustomobject]@{ Path = 'C:\Windows\Logs\CBS'; Mode = 'clear'  },
    [pscustomobject]@{ Path = 'C:\ESD';              Mode = 'report' }
)
Write-Log '   -- Residuo de atualizacao do Windows:'
$leftoverFound = @()
foreach ($t in $upgradeTargets) {
    if (-not (Test-Path -LiteralPath $t.Path)) { continue }
    $sz = (Measure-Tree -Root $t.Path -KeyDepth 0)[$t.Path.TrimEnd('\')]
    $gb = if ($sz) { Format-GB $sz.Loc } else { '0,00' }
    $tag = switch ($t.Mode) { 'tree' { 'remover' } 'clear' { 'esvaziar' } default { 'somente relatorio' } }
    Write-Log ('      {0,8} GB  {1}  ({2})' -f $gb, $t.Path, $tag)
    if ($t.Mode -eq 'report') {
        [void]$script:Pending.Add(
            ('{0} ocupa {1} GB - avaliar manualmente (em alguns OEM e midia de recuperacao)' -f $t.Path, $gb))
    } else {
        $leftoverFound += $t
    }
}
if (-not $leftoverFound.Count) { Write-Log '      Nenhum residuo de atualizacao removivel.' }

# -- Downloads (somente relatorio: e arquivo do usuario)
$dlRollup = Get-Rollup -Agg $usersAgg -Root 'C:\Users' -Depth 2
foreach ($k in ($dlRollup.Keys | Where-Object { $_ -like '*\Downloads' })) {
    $row = $dlRollup[$k]
    if ($row.Loc -lt 3GB) { continue }
    Write-Log ('   -- Downloads com {0} GB: {1}' -f (Format-GB $row.Loc), $k)
    Write-Log '      (NAO apago: e arquivo do usuario. Maiores itens:)'
    Get-ChildItem -LiteralPath $k -File -Recurse -Force -ErrorAction SilentlyContinue |
        Sort-Object -Property Length -Descending | Select-Object -First 15 | ForEach-Object {
            Write-Log ('      {0,8} GB  {1}' -f (Format-GB $_.Length), $_.Name)
        }
    [void]$script:Pending.Add(
        ('Pasta Downloads com {0} GB em {1}: revisar com o usuario o que pode ' +
         'ser descartado ou movido para o SharePoint.') -f (Format-GB $row.Loc), $k)
}

# -- Perfis no equipamento
Write-Log '   -- Perfis de usuario no equipamento:'
$profRollup = Get-Rollup -Agg $usersAgg -Root 'C:\Users' -Depth 1
foreach ($p in $script:Profiles) {
    $row = $profRollup[$p.FullName.TrimEnd('\')]
    $gb  = if ($row) { Format-GB $row.Loc } else { '0,00' }
    Write-Log ('      {0,8} GB  {1}   (ultimo acesso: {2:dd/MM/yyyy})' -f `
                $gb, $p.Name, $p.LastWriteTime)
}
Write-Log '   (NAO remova perfis por script - confirme com o usuario e use'
Write-Log '    Configuracoes > Contas > Outros usuarios.)'
Stop-Step $st

if (-not $Auto) {
    Write-Head 'Fim do diagnostico. Agora as acoes de limpeza.'
    Wait-Enter
}

# ==================================================================
#  [4/12] Windows Update: pacotes baixados + Delivery Optimization
#  Feito ANTES de disparar o DISM para nao competir pela pilha de
#  manutencao nem pelos servicos que precisam parar.
# ==================================================================
$st = Start-Step 'Windows Update (download + Delivery Optimization)'
Write-Log ''
Write-Log '[4/12] WINDOWS UPDATE - pacotes baixados e cache do Delivery Optimization'
Write-Log '   Ganho tipico: 1-8 GB. Rapido.'
if (Confirm-Step 'Aplicar?' $true) {
    foreach ($svc in @('wuauserv', 'bits', 'dosvc', 'usosvc')) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    }
    Clear-FolderContent 'C:\Windows\SoftwareDistribution\Download'
    foreach ($svc in @('bits', 'wuauserv')) {
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
    Write-Log '   Pacotes baixados do Windows Update removidos.'
    if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
        try {
            Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
            Write-Log '   Cache do Delivery Optimization limpo.'
        } catch { Write-Log '   Delivery Optimization: nada a limpar.' }
    }
    [void]$script:Applied.Add('Windows Update: pacotes baixados e cache do Delivery Optimization removidos')
} else {
    [void]$script:Skipped.Add('Windows Update (download/DO)')
}
Stop-Step $st

# ==================================================================
#  [5/12] DISM /StartComponentCleanup /ResetBase EM BACKGROUND
#  Era a maior mordida de tempo da v1 (5-15 min bloqueando o tecnico).
#  Agora roda enquanto as etapas interativas acontecem. O cleanmgr
#  NAO pode rodar junto - por isso a espera fica na etapa 11.
# ==================================================================
$dismProc = $null
$dismLog  = Join-Path $OutDir 'dism.log'
Write-Log ''
Write-Log '[5/12] WINSXS (componentes antigos) - DISM /ResetBase'
Write-Log '   Ganho tipico: 3-12 GB. Demora 5-15 min, mas roda em segundo'
Write-Log '   plano: siga respondendo as proximas etapas.'
Write-Log '   O /ResetBase impede desinstalar atualizacoes ja aplicadas.'
if ((-not $NoDism) -and (Confirm-Step 'Disparar em segundo plano?' $true)) {
    try {
        $dismProc = Start-Process -FilePath "$env:SystemRoot\System32\Dism.exe" `
                        -ArgumentList '/Online', '/Cleanup-Image', '/StartComponentCleanup', '/ResetBase' `
                        -RedirectStandardOutput $dismLog -WindowStyle Hidden -PassThru
        Write-Log ('   DISM iniciado em segundo plano (PID {0}). Log: {1}' -f $dismProc.Id, $dismLog)
    } catch {
        Write-Log ('   Falha ao iniciar o DISM: {0}' -f $_.Exception.Message)
    }
} else {
    [void]$script:Skipped.Add('DISM /StartComponentCleanup /ResetBase')
}

# ==================================================================
#  [6/12] Windows.old e residuo de atualizacao
#  A v1 delegava isso ao cleanmgr grafico. Na pratica a caixa
#  "Instalacoes anteriores do Windows" nao era marcada e sobravam
#  dezenas de GB. Agora e explicito.
# ==================================================================
$st = Start-Step 'Windows.old e residuo de atualizacao'
Write-Log ''
Write-Log '[6/12] WINDOWS.OLD E RESIDUO DE ATUALIZACAO'
if ($leftoverFound.Count) {
    Write-Log ('   Encontrado: {0}' -f ($leftoverFound.Path -join ', '))
    Write-Log '   ATENCAO: removendo C:\Windows.old voce perde a opcao de'
    Write-Log '   reverter a atualizacao do Windows para a versao anterior.'
    Write-Log '   O Windows apagaria sozinho em ~10 dias; aqui e agora.'
    if (Confirm-Step 'Remover residuo de atualizacao?' $RemoveWindowsOld.IsPresent) {
        foreach ($t in $leftoverFound) {
            if ($t.Mode -eq 'clear') {
                Clear-FolderContent $t.Path
                Write-Log ('   Esvaziado: {0}' -f $t.Path)
                [void]$script:Applied.Add(('Esvaziado {0}' -f $t.Path))
            } elseif (Remove-ProtectedTree $t.Path) {
                Write-Log ('   Removido: {0}' -f $t.Path)
                [void]$script:Applied.Add(('Removido {0}' -f $t.Path))
            } else {
                Write-Log ('   Nao foi possivel remover por completo: {0}' -f $t.Path)
                [void]$script:Pending.Add(
                    ('Remover {0} manualmente (Limpeza de Disco > Limpar arquivos do sistema)' -f $t.Path))
            }
        }
    } else {
        [void]$script:Skipped.Add('Remocao de Windows.old / residuo de atualizacao')
        [void]$script:Pending.Add(
            ('Residuo de atualizacao ainda ocupa disco: {0}' -f ($leftoverFound.Path -join ', ')))
    }
} else {
    Write-Log '   Nada a remover.'
}
Stop-Step $st

# ==================================================================
#  [7/12] Temp, lixeira, dumps
# ==================================================================
$st = Start-Step 'Temp, lixeira e dumps'
Write-Log ''
Write-Log '[7/12] TEMPORARIOS, LIXEIRA E DUMPS'
Write-Log '   Ganho tipico: 1-6 GB.'
if (Confirm-Step 'Aplicar?' $true) {
    foreach ($p in $script:Profiles) {
        foreach ($sub in @('AppData\Local\Temp',
                           'AppData\Local\CrashDumps',
                           'AppData\Local\D3DSCache',
                           'AppData\Local\Microsoft\Windows\WER\ReportArchive',
                           'AppData\Local\Microsoft\Windows\WER\ReportQueue')) {
            Clear-FolderContent (Join-Path $p.FullName $sub)
        }
    }
    Write-Log '   Temp, CrashDumps, D3DSCache e WER dos perfis limpos (itens em uso ignorados).'

    Clear-FolderContent 'C:\Windows\Temp'
    Clear-FolderContent 'C:\Windows\LiveKernelReports'
    Clear-FolderContent 'C:\Windows\Minidump'
    Write-Log '   C:\Windows\Temp, LiveKernelReports e Minidump limpos.'

    if (Test-Path -LiteralPath 'C:\Autodesk') {
        # C:\Autodesk e extracao de instalador, nao instalacao.
        if (Confirm-Step 'Remover C:\Autodesk (extracao de instalador)?' $true) {
            Remove-Item -LiteralPath 'C:\Autodesk' -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log '   C:\Autodesk removido.'
            [void]$script:Applied.Add('Removido C:\Autodesk (extracao de instalador)')
        }
    }

    try {
        Clear-RecycleBin -Force -ErrorAction Stop
        Write-Log ('   Lixeira de {0} esvaziada.' -f $env:USERNAME)
    } catch { Write-Log ('   Lixeira de {0}: nada a esvaziar.' -f $env:USERNAME) }

    [void]$script:Applied.Add('Temporarios, dumps e lixeira do operador limpos')

    Write-Log ''
    Write-Log '   A lixeira e por usuario. Rodando como admin, a lixeira do'
    Write-Log '   usuario da maquina NAO foi tocada. Esvaziar a de todos e'
    Write-Log '   IRREVERSIVEL (arquivos descartados se perdem).'
    if (Confirm-Step 'Esvaziar a lixeira de TODOS os perfis?' $EmptyAllRecycleBins.IsPresent) {
        Get-ChildItem 'C:\$Recycle.Bin' -Directory -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Clear-FolderContent $_.FullName }
        Write-Log '   Lixeira de todos os perfis esvaziada.'
        [void]$script:Applied.Add('Lixeira de todos os perfis esvaziada')
    } else {
        [void]$script:Pending.Add('Usuario deve esvaziar a propria lixeira na sessao dele')
    }
} else {
    [void]$script:Skipped.Add('Temporarios / lixeira / dumps')
}
Stop-Step $st

# ==================================================================
#  [8/12] Caches de Teams, Edge, Chrome
# ==================================================================
$st = Start-Step 'Caches de navegador e Teams'
Write-Log ''
Write-Log '[8/12] CACHES DE TEAMS, EDGE E CHROME'
Write-Log '   Remove somente pasta de cache. Senha, favorito e conversa ficam.'
Write-Log '   Os programas precisam estar FECHADOS. Ganho tipico: 1-6 GB.'
if (Confirm-Step 'Aplicar?' $true) {
    $cacheNames = @('Cache', 'Code Cache', 'GPUCache', 'DawnGraphiteCache',
                    'DawnWebGPUCache', 'Service Worker\CacheStorage')
    foreach ($p in $script:Profiles) {
        # Teams classico
        $tc = Join-Path $p.FullName 'AppData\Roaming\Microsoft\Teams'
        if (Test-Path -LiteralPath $tc) {
            Get-ChildItem -LiteralPath $tc -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like '*Cache*' } |
                ForEach-Object { Clear-FolderContent $_.FullName }
        }
        # Teams novo (MSIX)
        $tn = Join-Path $p.FullName 'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache'
        if (Test-Path -LiteralPath $tn) {
            Get-ChildItem -LiteralPath $tn -Directory -Recurse -Force -Filter 'Cache' -ErrorAction SilentlyContinue |
                ForEach-Object { Clear-FolderContent $_.FullName }
        }
        # Edge e Chrome: um cache por profile do navegador
        foreach ($ud in @('AppData\Local\Microsoft\Edge\User Data',
                          'AppData\Local\Google\Chrome\User Data')) {
            $root = Join-Path $p.FullName $ud
            if (-not (Test-Path -LiteralPath $root)) { continue }
            Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
                ForEach-Object {
                    foreach ($c in $cacheNames) {
                        Clear-FolderContent (Join-Path $_.FullName $c)
                    }
                }
        }
    }
    Write-Log '   Caches de Teams, Edge e Chrome limpos.'
    [void]$script:Applied.Add('Caches de Teams, Edge e Chrome limpos')
} else {
    [void]$script:Skipped.Add('Caches de Teams/Edge/Chrome')
}
Stop-Step $st

# ==================================================================
#  [9/12] Hibernacao
# ==================================================================
Write-Log ''
Write-Log '[9/12] HIBERNACAO (libera arquivo do tamanho da RAM)'
Write-Log '   Desativa tambem a Inicializacao Rapida e a opcao de hibernar.'
Write-Log '   Se o usuario hiberna o notebook, responda N.'
if (Confirm-Step 'Desligar hibernacao?' $DisableHibernation.IsPresent) {
    & powercfg.exe /h off | Out-Null
    Write-Log '   Hibernacao desligada (reversivel com: powercfg /h on).'
    [void]$script:Applied.Add('Hibernacao desligada (hiberfil.sys liberado)')
} else {
    [void]$script:Skipped.Add('Desligar hibernacao')
}

# ==================================================================
#  [10/12] Desidratar pasta de nuvem
# ==================================================================
$st = Start-Step 'Desidratacao de pasta de nuvem'
Write-Log ''
Write-Log '[10/12] DESIDRATAR PASTA DE NUVEM'
Write-Log '   Converte arquivos de OneDrive/SharePoint para "somente na nuvem".'
Write-Log '   NADA e apagado: os arquivos continuam no SharePoint e voltam a'
Write-Log '   baixar quando o usuario abrir. E reversivel.'

# Sugere o candidato a partir da varredura da etapa 2, em vez de o
# tecnico ter que copiar caminho na mao.
$cloudCandidates = $usersAgg.Values |
    Where-Object { $_.Loc -gt 5GB -and $_.Path -notlike '*\AppData\*' } |
    Sort-Object -Property Loc -Descending | Select-Object -First 5
if ($cloudCandidates) {
    Write-Log '   Candidatos pela varredura (maiores pastas fora de AppData):'
    foreach ($c in $cloudCandidates) {
        Write-Log ('      {0,8} GB   {1}' -f (Format-GB $c.Loc), $c.Path)
    }
}

$target = $CloudPath
if (-not $target -and -not $Auto) {
    Write-Log '   Cole o caminho da pasta de nuvem (Enter para pular):'
    $target = (Read-Host '   Caminho').Trim('"').Trim()
}
if ($target -and (Test-Path -LiteralPath $target -PathType Container)) {
    $oneDriveUp = @(Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue).Count -gt 0
    if (-not $oneDriveUp) {
        Write-Log '   AVISO: OneDrive.exe nao esta rodando nesta sessao. A'
        Write-Log '   desidratacao pode nao ser aplicada pelo sync engine.'
    }
    if (Confirm-Step ('Desidratar "{0}"?' -f $target) $true) {
        Push-Location -LiteralPath $target
        & attrib.exe -P +U /S /D * 2>&1 | Out-Null
        Pop-Location
        $after = (Measure-Tree -Root $target -KeyDepth 0)[$target.TrimEnd('\')]
        Write-Log ('   Concluido. Agora {0} GB no disco (de {1} GB totais).' -f `
                    (Format-GB $after.Loc), (Format-GB $after.Tot))
        Write-Log '   Confirme no Explorador: icone de nuvem em vez de check verde.'
        [void]$script:Applied.Add("Pasta de nuvem desidratada: $target")
    }
} elseif ($target) {
    Write-Log ('   Caminho nao encontrado: {0}' -f $target)
} else {
    Write-Log '   Etapa pulada.'
    [void]$script:Skipped.Add('Desidratacao de pasta de nuvem')
}
Stop-Step $st

# ==================================================================
#  [11/12] Espera o DISM e, so depois, oferece o cleanmgr
#  cleanmgr e DISM disputam a pilha de manutencao: rodando juntos um
#  deles falha com "outra operacao em andamento".
# ==================================================================
Write-Log ''
Write-Log '[11/12] FECHAMENTO DAS TAREFAS DE SEGUNDO PLANO'
if ($dismProc) {
    Write-Log '   Aguardando o DISM terminar (ele rodou durante as etapas acima)...'
    $st = Start-Step 'Espera do DISM'
    try {
        $dismProc.WaitForExit()
        Write-Log ('   DISM finalizado com codigo {0}. Log: {1}' -f $dismProc.ExitCode, $dismLog)
        if ($dismProc.ExitCode -eq 0) {
            [void]$script:Applied.Add('WinSxS compactado (DISM /StartComponentCleanup /ResetBase)')
        } else {
            [void]$script:Pending.Add(('DISM terminou com codigo {0} - conferir {1}' -f $dismProc.ExitCode, $dismLog))
        }
    } catch {
        Write-Log ('   Falha ao aguardar o DISM: {0}' -f $_.Exception.Message)
    }
    Stop-Step $st
} else {
    Write-Log '   DISM nao foi executado nesta rodada.'
}

if (-not $Auto) {
    Write-Log ''
    Write-Log '   Para pontos de restauracao antigos e itens que so o assistente'
    Write-Log '   grafico cobre, use a Limpeza de Disco > Limpar arquivos do sistema.'
    if (Confirm-Step 'Abrir a Limpeza de Disco agora?' $false) {
        Start-Process -FilePath 'cleanmgr.exe' -ArgumentList '/d', 'C:'
        Wait-Enter 'Conclua na janela que abriu e de Enter aqui'
    }
}

# ==================================================================
#  [12/12] Prevencao + resultado
# ==================================================================
Write-Log ''
Write-Log '[12/12] PREVENCAO - Sensor de Armazenamento'
Write-Log ('   Configuracao POR PERFIL. Vai valer para {0} (conta logada agora).' -f $env:USERNAME)
Write-Log '   NAO ativa limpeza da pasta Downloads (apagaria arquivo do usuario).'
if (Confirm-Step ('Ativar para {0}?' -f $env:USERNAME) $true) {
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
    if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
    Set-ItemProperty -Path $k -Name '01' -Value 1 -Type DWord
    Set-ItemProperty -Path $k -Name '04' -Value 1 -Type DWord
    Write-Log ('   Sensor de Armazenamento ativado para {0}.' -f $env:USERNAME)
    [void]$script:Applied.Add("Sensor de Armazenamento ativado para $env:USERNAME")
    # E configuracao por perfil (HKCU). Rodando elevado, quase sempre a conta
    # logada nao e a do usuario da maquina - por isso a pendencia e incondicional.
    [void]$script:Pending.Add('Confirmar/ativar o Sensor de Armazenamento tambem na sessao do usuario da maquina')
}

[void]$script:Pending.Add('Confirmar "Arquivos sob Demanda" ativo no OneDrive do usuario e orientar a NAO marcar biblioteca inteira como "Sempre manter neste dispositivo"')

$runStart.Stop()
$d1   = Get-DriveC
$gain = $d1.Free - $d0.Free
$pct  = ($d1.Free / $d1.Total) * 100

Write-Head 'RESULTADO'
Write-Log ('   Antes: {0} GB livre   ->   Agora: {1} GB livre' -f (Format-GB $d0.Free), (Format-GB $d1.Free))
Write-Log ('   Ganho: {0} GB   |   Disco: {1:N1}% livre' -f (Format-GB $gain), $pct)
Write-Log ('   Tempo total de execucao: {0:N1} min' -f $runStart.Elapsed.TotalMinutes)
Write-Log ''
Write-Log '   Tempo por etapa:'
foreach ($t in $script:Timings) { Write-Log ('      {0,6:N1}s  {1}' -f $t.Segundos, $t.Etapa) }

Write-Log ''
Write-Log '   Aplicado:'
if ($script:Applied.Count) { foreach ($a in $script:Applied) { Write-Log "      - $a" } }
else { Write-Log '      (nada)' }

if ($script:Pending.Count) {
    Write-Log ''
    Write-Log '   Pendente / proximo passo:'
    foreach ($p in $script:Pending) { Write-Log "      - $p" }
}

Write-Log ''
Write-Log '   Referencia de decisao:'
Write-Log '      acima de 15% livre .... equipamento normalizado, pode fechar'
Write-Log '      abaixo de 15% livre ... avaliar apps instalados (o maior pote'
Write-Log '                              costuma ser AutoCAD/Revit) ou escalar'
Write-Log '                              upgrade de SSD / troca de equipamento'
Write-Log ''
Write-Log '   Desfazer, se precisar:'
Write-Log '      hibernacao ........ powercfg /h on'
Write-Log '      pasta de nuvem .... botao direito > "Sempre manter neste dispositivo"'

# ------------------------------------------------------------------
#  Artefatos para o chamado
# ------------------------------------------------------------------
$summary = [pscustomobject]@{
    Maquina          = $env:COMPUTERNAME
    Data             = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
    Operador         = "$env:USERDOMAIN\$env:USERNAME"
    Modo             = $(if ($Auto) { 'automatico' } else { 'interativo' })
    DiscoTotalGB     = [double]((Format-GB $d0.Total) -replace ',', '.')
    LivreAntesGB     = [double]((Format-GB $d0.Free)  -replace ',', '.')
    LivreDepoisGB    = [double]((Format-GB $d1.Free)  -replace ',', '.')
    GanhoGB          = [double]((Format-GB $gain)     -replace ',', '.')
    PercentualLivre  = [math]::Round($pct, 1)
    MinutosExecucao  = [math]::Round($runStart.Elapsed.TotalMinutes, 1)
    Aplicado         = @($script:Applied)
    Pulado           = @($script:Skipped)
    Pendente         = @($script:Pending)
    TempoPorEtapa    = @($script:Timings)
    MaioresPastas    = @($script:Findings)
}
$jsonPath = Join-Path $OutDir 'resumo_limpeza.json'
[IO.File]::WriteAllText($jsonPath, ($summary | ConvertTo-Json -Depth 5), $script:Utf8)

$csvPath = Join-Path $OutDir 'maiores_pastas.csv'
$script:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# HTML pronto para colar como acao no chamado da ferramenta de ITSM.
# Sem <p> e sem <code>: alguns campos de ITSM renderizam essas tags literais.
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine(('<b>Limpeza de armazenamento executada em {0}</b><br><br>' -f $env:COMPUTERNAME))
[void]$sb.AppendLine(('Espaco livre antes: <b>{0} GB</b><br>' -f (Format-GB $d0.Free)))
[void]$sb.AppendLine(('Espaco livre depois: <b>{0} GB</b><br>' -f (Format-GB $d1.Free)))
[void]$sb.AppendLine(('Ganho: <b>{0} GB</b> ({1:N1}% do disco livre)<br><br>' -f (Format-GB $gain), $pct))
[void]$sb.AppendLine('<b>O que foi feito</b><ul>')
foreach ($a in $script:Applied) { [void]$sb.AppendLine("<li>$a</li>") }
[void]$sb.AppendLine('</ul>')
if ($script:Pending.Count) {
    [void]$sb.AppendLine('<b>Proximos passos</b><ul>')
    foreach ($p in $script:Pending) { [void]$sb.AppendLine("<li>$p</li>") }
    [void]$sb.AppendLine('</ul>')
}
$htmlPath = Join-Path $OutDir 'acao_chamado.html'
[IO.File]::WriteAllText($htmlPath, $sb.ToString(), $script:Utf8)

Write-Log ''
Write-Log ('   Log ............... {0}' -f $script:LogPath)
Write-Log ('   Resumo JSON ....... {0}' -f $jsonPath)
Write-Log ('   Maiores pastas CSV. {0}' -f $csvPath)
Write-Log ('   Acao p/ chamado ... {0}' -f $htmlPath)

if (-not $Auto) { Wait-Enter 'Enter para sair' }
