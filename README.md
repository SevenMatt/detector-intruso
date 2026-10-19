# Detector de Intrusos

Ferramenta de triagem e resposta rápida a incidentes (IR) para Windows e Linux.
Detecta processos suspeitos, conexões de C2, mecanismos de persistência,
contas comprometidas e arquivos modificados recentemente e pode conter
o intruso automaticamente.

## Instalação

### Opção 1  Executável pronto (sem Python) Recomendado

Baixe o executável do seu sistema na aba
[**Releases**](https://github.com/SevenMatt/detector-intrusos/releases):

| Sistema | Arquivo              
| Windows | `DetectorIntruso.exe`
| Linux   | `detector_intruso`   

**Windows:**
1. Baixe `DetectorIntruso.exe`.
2. Abra o **PowerShell como Administrador** na pasta do download.
3. Execute:
   ```powershell
   .\DetectorIntruso.exe --detect

## Linux:
chmod +x detector_intruso
sudo ./detector_intruso --detect


## Opção 2  Clonar com Git
git clone https://github.com/SevenMatt/detector-intrusos.git
cd detector-intrusos

## Opção 3  Baixar sem Git
Na página do repositório, clique em Code, Download ZIP, descompacte e siga para "Executando com Python" abaixo.

## Executando com Python
Requisito: Python 3.6+. Sem dependências externas (usa apenas a biblioteca padrão).

`Windows (PowerShell como Administrador):`
python detector_intruso.py --detect

`Linux / WSL:`
sudo python3 detector_intruso.py --detect
**Usuários WSL: o script roda no ambiente Linux do WSL, mas para escanear o Windows host use o .exe no PowerShell.**

## Uso rápido
python detector_intruso.py --detect # apenas detecção
python detector_intruso.py --respond # detecção + contenção (pede confirmação)

## Requisitos
Python 3.6+ (ou use o executável da seção Releases)
Privilégios de administrador/root (obrigatório no modo --respond)


## Aviso
`Ferramenta para resposta a incidentes em sistemas próprios ou com autorização explícita. Revise as ações antes de confirmar a contenção. Use em ambiente de teste antes de aplicar em produção.`