@echo off
REM ============================================================
REM  LIMPEZA DE ARMAZENAMENTO / DISCO CHEIO - v2 (launcher)
REM
REM  Toda a logica vive em limpeza-disco.ps1, ao lado deste arquivo.
REM  A v1 monolitica esta preservada em limpeza-disco.v1.bat.
REM
REM  Motivo da separacao: na v1 cada etapa abria um powershell.exe
REM  novo (12 processos) e o log saia ilegivel porque o Tee-Object
REM  gravava UTF-16 enquanto os echo do cmd gravavam OEM. Um unico
REM  processo resolve os dois problemas e ainda deixa o codigo
REM  legivel sem escapar aspas dentro de aspas.
REM
REM  A elevacao acontece dentro do .ps1: o PowerShell monta a linha
REM  de comando com as aspas corretas para caminho com espaco, o
REM  que o Start-Process do .bat da v1 nao fazia.
REM
REM  USO
REM    limpeza-disco.bat
REM        Interativo, pergunta S/N em cada etapa (padrao).
REM
REM    limpeza-disco.bat -Auto
REM        Sem interacao. Aplica so o que e seguro sem supervisao:
REM        temp, caches, Windows Update, DISM, Sensor de
REM        Armazenamento. NAO mexe em Windows.old, hibernacao,
REM        lixeira de terceiros nem desidratacao.
REM
REM    limpeza-disco.bat -Auto -RemoveWindowsOld
REM        Idem, autorizando remover a instalacao anterior do
REM        Windows (perde a opcao de reverter a atualizacao).
REM
REM    limpeza-disco.bat -CloudPath "C:\Users\<usuario>\<Empresa>\<Biblioteca>"
REM        Desidrata a pasta de nuvem informada.
REM
REM    limpeza-disco.bat -NoDism
REM        Pula o DISM /ResetBase (etapa mais demorada).
REM
REM  Autor: Jonatas Alves - Licenca MIT
REM ============================================================

chcp 65001 >nul
title Limpeza de Armazenamento (v2)

set "PS1=%~dp0limpeza-disco.ps1"
if not exist "%PS1%" (
    echo ERRO: nao encontrei "%PS1%"
    echo O .bat e o .ps1 precisam estar na mesma pasta.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
exit /b %errorlevel%
