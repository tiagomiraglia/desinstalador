# Desinstalador Completo

Um desinstalador avançado para Windows com interface gráfica, desenvolvido em Python. Permite desinstalar programas de forma completa, limpar resíduos, matar processos, escanear por malware usando a API do VirusTotal e muito mais.

## Funcionalidades

- **Lista de Programas Instalados**: Exibe todos os programas instalados no registro do Windows.
- **Desinstalação Completa**: Remove programas, mata processos relacionados, limpa arquivos residuais, remove entradas do registro e gera relatórios.
- **Limpeza Profunda**: Remove arquivos temporários, cache e lixeira.
- **Limpeza de Registro**: Remove entradas órfãs do registro de desinstalação.
- **Scan por Malware**: Varre processos e arquivos de inicialização, verifica hashes no VirusTotal para detectar malware.
- **Remoção Segura de Malware**: Permite matar processos ou deletar arquivos confirmados como maliciosos pelo VirusTotal.
- **Gerenciamento de Processos**: Lista processos em execução em tempo real e permite terminá-los.
- **Monitoramento do Sistema**: Exibe uso de CPU, memória e armazenamento em tempo real.
- **Interface Gráfica Compacta**: Botões no lado esquerdo, listas de programas e processos lado a lado no direito, barra de progresso e logs.

## Requisitos

- **Sistema Operacional**: Windows 10 ou superior.
- **Python**: Versão 3.6 ou superior (para executar o script).
- **Bibliotecas**: 
  - `tkinter` (incluído no Python padrão).
  - `requests` (instale com `pip install requests`).
  - `psutil` (instale com `pip install psutil`).
  - `Pillow` (instale com `pip install pillow`).
- **Privilégios**: Deve ser executado como administrador para acessar registro e matar processos.
- **API do VirusTotal**: Obtenha uma chave gratuita em [VirusTotal](https://www.virustotal.com/gui/join-us). Substitua `VIRUSTOTAL_API_KEY` no código.

## Instalação e Execução

### Opção 1: Executar o Script Python
1. Clone ou baixe o repositório: `git clone https://github.com/tiagomiraglia/desinstalador.git`
2. Instale as dependências: `pip install requests psutil pillow`
3. Edite o arquivo `desinstalador.py` e substitua `VIRUSTOTAL_API_KEY` pela sua chave da API do VirusTotal.
4. Execute como administrador: `python desinstalador.py`.

### Opção 2: Executar o Executável (Recomendado para Usuários Finais)
- Baixe o arquivo `desinstalador.exe` do repositório (na raiz).
- Execute o `.exe` como administrador (botão direito > Executar como administrador).
- O executável é standalone e não requer Python instalado.

## Como Usar

1. **Executar**: Rode o script ou exe como administrador.
2. **Selecionar Programa**: Na aba "Programas", selecione o que deseja desinstalar.
3. **Desinstalar**: Clique em "Desinstalar Selecionado". O processo inclui várias etapas com progresso em tempo real.
4. **Outras Ações**:
   - **Limpeza Profunda**: Remove arquivos temporários (barra de progresso).
   - **Limpeza de Registro**: Remove entradas órfãs (barra de progresso).
   - **Scan Malware**: Varre por malware usando VirusTotal (requer API key, barra de progresso).
   - **Remover Malware**: Selecione na aba "Malware" e confirme remoção.
   - **Matar Processo**: Na aba "Processos", selecione e termine.
   - **Atualizar Listas**: Refresque programas ou processos.
5. **Monitor Sistema**: Veja CPU, Memória e Armazenamento no painel esquerdo (atualiza a cada 2s).
6. **Logs**: Todas as ações são logadas em `desinstalador.log` e exibidas na interface.

## Geração de Executável

Para criar um executável standalone:

1. Instale PyInstaller: `pip install pyinstaller`.
2. Execute: `python -m pyinstaller --onefile desinstalador.py`.
3. O executável será gerado em `desinstalador.exe` (na raiz).

**Nota**: O executável requer privilégios de administrador. Configure um atalho para "Executar como administrador" se desejar.

## Avisos

- **Backup**: A desinstalação cria backups em `temp`. Verifique antes de remover.
- **Malware**: Remoção baseada no VirusTotal. Use com cautela.
- **Responsabilidade**: Use por sua conta e risco. Teste em ambiente seguro.
- **API Limits**: VirusTotal tem limites gratuitos (4 requests/min, 500/dia).

## Repositório

Código fonte e executável disponível em: [https://github.com/tiagomiraglia/desinstalador](https://github.com/tiagomiraglia/desinstalador)

## Contribuição

Contribuições são bem-vindas! Abra issues ou pull requests.

## Licença

Este projeto é open-source sob a licença MIT. Use e modifique conforme necessário.