# Detector de Intrusos

Ferramenta de triagem e resposta rápida a incidentes (IR) para Windows e Linux.
Detecta processos suspeitos, conexões de C2, mecanismos de persistência,
contas comprometidas e arquivos modificados recentemente — e pode conter
o intruso automaticamente.

## Uso rápido

python detector_intruso.py --detect     # apenas detecção
python detector_intruso.py --respond    # detecção + contenção (pede confirmação)

## Requisitos
- Python 3.6+ (ou use o executável da seção Releases)
- Privilégios de administrador/root (obrigatório no modo --respond)

## O que ele faz
 !!Módulo!!            !!Detalhe!!                                               
Processos          Varre comandos em busca de ferramentas de ataque       
Rede               Detecta conexões em portas típicas de C2 (4444, 31337…)
Persistência       Run keys, tarefas agendadas, cron, .bashrc             
Contas             UID 0 duplicado (Linux), admins novos (Windows)        
Arquivos           Executáveis recentes em /tmp, Temp, etc.               


## Contenção (--respond)
1. Bloqueia os IPs do invasor no firewall (entrada e saída)
2. Encerra conexões ativas e mata processos suspeitos
3. Remove persistência (Run keys, cron, tarefas)
4. Remove contas comprometidas

## Aviso
Ferramenta para resposta a incidentes em sistemas próprios ou com autorização
explícita. Revise as ações antes de confirmar a contenção. Use em ambiente de
teste antes de aplicar em produção.

## Licença
MIT