# limpeza-disco

Script PowerShell para atender chamados de **"disco cheio / computador lento"** em
estações Windows de forma padronizada: primeiro mede, depois limpa com confirmação
etapa a etapa, e no fim entrega um relatório pronto para anexar ao chamado.

> **Resultado medido em atendimento real (ago/2026):** espaço livre no `C:` foi de
> **22,75 GB para 44,58 GB** (+21,84 GB liberados, disco com 18,7% livre), sem
> apagar nenhum documento do usuário.

---

## Problema

Disco cheio é um dos chamados mais recorrentes do suporte e a causa quase nunca é
"arquivo do usuário". Na prática o espaço está em resíduo de atualização do Windows,
caches, OST do Outlook e pastas de nuvem sincronizadas por inteiro. A limpeza manual
dependia de quem atendia, e a primeira versão automatizada (um `.bat` monolítico)
tinha problemas concretos:

- **Log ilegível**: `Tee-Object` gravava UTF-16 e os `echo` do cmd gravavam OEM no
  mesmo arquivo.
- **Varredura em dobro**: `C:\Users` era percorrido em duas etapas, e a junction
  `C:\Users\All Users → C:\ProgramData` era contada (e varrida) duas vezes.
- **DISM bloqueante**: `/StartComponentCleanup /ResetBase` travava o técnico por
  5–15 min.
- **`Windows.old` ficava no disco**: a remoção era delegada ao assistente gráfico da
  Limpeza de Disco; na prática a caixa não era marcada e sobravam 51 GB.
- **Pasta de nuvem mal medida**: só o atributo `OFFLINE` era testado, então pasta já
  desidratada aparecia como se ocupasse disco.

## Solução

Reescrita em um único processo PowerShell (`limpeza-disco.ps1`), com o `.bat` só
como lançador. São 12 etapas em duas fases:

| Fase | Etapas |
|---|---|
| **Diagnóstico** (somente leitura) | espaço do `C:`, varredura única da raiz e dos perfis, suspeitos nomeados (OST do Outlook, resíduo de upgrade, Downloads grandes, perfis) |
| **Ações** (cada uma pede S/N) | Windows Update + Delivery Optimization, DISM `/ResetBase` **em segundo plano**, `Windows.old` e resíduo de upgrade, temporários/dumps/lixeira, caches de Teams/Edge/Chrome, hibernação, desidratação de pasta OneDrive/SharePoint, Sensor de Armazenamento |

Ordem de ganho observada em campo (anotada no cabeçalho do script):

| Alvo | Ganho típico |
|---|---|
| `C:\Windows.old` | 20–60 GB |
| Desidratar biblioteca de nuvem | 10–52 GB |
| OST do Outlook (reduzir janela offline) | 10–30 GB |
| Limpeza de Disco / Windows Update | 4–20 GB |
| Temp, lixeira e caches | 1–6 GB |

### O que o script **não** faz

- Não apaga documentos, Downloads nem perfis de usuário (só relata e sugere).
- Não toca em agentes de segurança e gestão (antivírus, DLP, MDM).
- Não desidrata nem remove `Windows.old` em modo automático sem flag explícita.

---

## Como usar

Requisitos: Windows 10/11, PowerShell 5.1+ e conta de administrador local (o script
se auto-eleva via UAC).

```bat
:: Interativo: pergunta S/N em cada etapa (padrão)
limpeza-disco.bat

:: Sem interação: só o que é seguro sem supervisão
:: (temp, caches, Windows Update, DISM, Sensor de Armazenamento)
limpeza-disco.bat -Auto

:: Idem, autorizando remover a instalação anterior do Windows
limpeza-disco.bat -Auto -RemoveWindowsOld

:: Desidratar uma pasta de nuvem específica
limpeza-disco.bat -CloudPath "C:\Users\<usuario>\<Empresa>\<Biblioteca>"

:: Pular o DISM /ResetBase (etapa mais demorada)
limpeza-disco.bat -NoDism
```

| Parâmetro | Efeito |
|---|---|
| `-Auto` | Não pergunta nada; aplica só as etapas seguras sem supervisão |
| `-RemoveWindowsOld` | Em `-Auto`, autoriza remover `C:\Windows.old` |
| `-DisableHibernation` | Em `-Auto`, autoriza `powercfg /h off` |
| `-EmptyAllRecycleBins` | Em `-Auto`, autoriza esvaziar a lixeira de todos os perfis |
| `-CloudPath <caminho>` | Pasta OneDrive/SharePoint a desidratar |
| `-NoDism` | Não roda `DISM /StartComponentCleanup /ResetBase` |
| `-OutDir <caminho>` | Onde gravar os relatórios (padrão: Área de Trabalho, ou `C:\ProgramData\LimpezaDisco` em `-Auto`) |

### Saídas

| Arquivo | Conteúdo |
|---|---|
| `log_limpeza.txt` | Log completo em UTF-8 |
| `resumo_limpeza.json` | Antes/depois, ganho, tempo por etapa, aplicado/pulado/pendente |
| `maiores_pastas.csv` | Maiores pastas na raiz e nos perfis (no disco × total na nuvem) |
| `acao_chamado.html` | Resumo em HTML simples, pronto para colar como ação no chamado |
| `dism.log` | Saída do DISM rodado em segundo plano |

> Os relatórios contêm nome da máquina e do operador. Não versione essas saídas
> (o `.gitignore` já as exclui).

---

## Resultados medidos

Atendimento real de lentidão e congelamento de tela em notebook (ago/2026), usando a
v2. Etapas aplicadas: Windows Update, remoção da instalação anterior do Windows,
temporários/logs/relatórios de falha, pasta de extração de instalador, caches de
Teams/Edge/Chrome, lixeira, hibernação desligada e Sensor de Armazenamento ativado.

| Métrica | Valor |
|---|---|
| Espaço livre antes | **22,75 GB** |
| Espaço livre depois | **44,58 GB** |
| Liberado | **21,84 GB** |
| Disco livre ao final | **18,7%** |

---

## Destaques técnicos

- **Varredura de disco própria** (`Measure-Tree`): caminhada iterativa com
  `System.IO.DirectoryInfo.Enumerate*`, sem seguir junction/symlink, com `try/catch`
  por diretório (Access Denied não aborta o ramo) e agregação em vários níveis numa
  única passada. `Get-Rollup` re-agrega o resultado em outra profundidade sem varrer
  o disco de novo.
- **Arquivos sob demanda medidos corretamente**: "no disco" × "total" usa
  `OFFLINE | RECALL_ON_DATA_ACCESS` (`0x401000`), não só `OFFLINE`.
- **DISM em paralelo com o atendimento**: dispara em segundo plano e só é aguardado
  antes de oferecer o `cleanmgr`, porque os dois disputam a pilha de manutenção.
- **Remoção robusta de `Windows.old`**: `takeown` + `icacls` com o SID
  `S-1-5-32-544` (o nome do grupo muda em Windows pt-BR) + `rd /s /q`.
- **Limpeza que não para no primeiro arquivo em uso**: caminho rápido em .NET, com
  fallback para `Remove-Item` só no ramo travado.
- **Auto-elevação no PowerShell**, repassando os parâmetros com aspas corretas para
  caminhos com espaço (o `Start-Process` do `.bat` antigo quebrava nesses casos).
- **Saída para humanos e máquinas**: log UTF-8 com um único escritor, JSON, CSV e
  HTML para o chamado.

---

## Avisos

- Remover `Windows.old` elimina a opção de reverter a atualização do Windows.
- `/ResetBase` impede desinstalar atualizações já aplicadas.
- Esvaziar a lixeira de todos os perfis é irreversível.
- Teste em uma máquina de laboratório antes de usar em produção. Use por sua conta e
  risco (ver [LICENSE](LICENSE)).

## Licença

[MIT](LICENSE) © Jonatas Alves
