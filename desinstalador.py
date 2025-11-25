import os
import shutil
import winreg
import sys
import logging
import subprocess
import ctypes
import tempfile
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox, scrolledtext, simpledialog
import hashlib
import requests
import psutil
import time
import threading
import re
from PIL import Image, ImageTk
import urllib.request
import io

VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"  # Substitua pela sua chave da API do VirusTotal

def is_admin():
    """Verifica se o script está rodando como administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Relaunch o script como administrador."""
    if not is_admin():
        print("Executando como administrador...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

run_as_admin()

logging.basicConfig(filename='desinstalador.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def calcular_hash_arquivo(caminho_arquivo):
    """Calcula o hash SHA256 de um arquivo."""
    try:
        with open(caminho_arquivo, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def verificar_virustotal(hash_arquivo):
    """Verifica o hash no VirusTotal usando a API."""
    if not VIRUSTOTAL_API_KEY:
        return "API key não fornecida."
    url = f"https://www.virustotal.com/api/v3/files/{hash_arquivo}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            return malicious, total  # Retorna tupla (malicious, total)
        elif response.status_code == 404:
            return 0, 0  # Não encontrado, assume não malicioso
        else:
            return None, None  # Erro
    except Exception as e:
        return None, None

def obter_info_instalacao(programa_chave):
    """Obtém o local de instalação e string de desinstalação do programa do registro."""
    try:
        chave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ)
        subchave = winreg.OpenKey(chave, programa_chave, 0, winreg.KEY_READ)
        local_instalacao = None
        uninstall_string = None
        try:
            local_instalacao, _ = winreg.QueryValueEx(subchave, "InstallLocation")
        except FileNotFoundError:
            pass
        try:
            uninstall_string, _ = winreg.QueryValueEx(subchave, "UninstallString")
        except FileNotFoundError:
            pass
        winreg.CloseKey(subchave)
        winreg.CloseKey(chave)
        return local_instalacao, uninstall_string
    except Exception as e:
        logging.error(f"Erro ao obter info de instalação: {e}")
        print(f"Erro ao obter info de instalação: {e}")
    return None, None

def listar_programas_instalados():
    """Lista todos os programas instalados no registro."""
    programas = []
    try:
        chave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                subchave_nome = winreg.EnumKey(chave, i)
                subchave = winreg.OpenKey(chave, subchave_nome, 0, winreg.KEY_READ)
                try:
                    nome_display, _ = winreg.QueryValueEx(subchave, "DisplayName")
                    programas.append((subchave_nome, nome_display))
                except FileNotFoundError:
                    pass
                winreg.CloseKey(subchave)
                i += 1
            except OSError:
                break
        winreg.CloseKey(chave)
    except Exception as e:
        logging.error(f"Erro ao listar programas instalados: {e}")
        print(f"Erro ao listar programas instalados: {e}")
    return programas

def remover_do_registro(programa_nome):
    """Remove entradas do registro de desinstalação."""
    try:
        chave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_ALL_ACCESS)
        i = 0
        while True:
            try:
                subchave = winreg.EnumKey(chave, i)
                if programa_nome.lower() in subchave.lower():
                    winreg.DeleteKey(chave, subchave)
                    logging.info(f"Entrada do registro removida: {subchave}")
                    print(f"Entrada do registro removida: {subchave}")
                i += 1
            except OSError:
                break
        winreg.CloseKey(chave)
    except Exception as e:
        if "Acesso negado" in str(e) or "Access is denied" in str(e):
            print("Erro ao remover do registro: Acesso negado. Execute o script como administrador para remover entradas do registro.")
        else:
            print(f"Erro ao remover do registro: {e}")
        logging.error(f"Erro ao remover do registro: {e}")

def limpeza_registro(callback=None):
    """Remove entradas órfãs do registro de desinstalação."""
    try:
        chave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_ALL_ACCESS)
        i = 0
        total_keys = 0
        # Count total keys
        while True:
            try:
                winreg.EnumKey(chave, i)
                total_keys += 1
                i += 1
            except OSError:
                break
        current = 0
        removidos = 0
        i = 0
        while True:
            try:
                subchave_nome = winreg.EnumKey(chave, i)
                if callback:
                    callback(current, total_keys, f"Registro: {subchave_nome}")
                subchave = winreg.OpenKey(chave, subchave_nome, 0, winreg.KEY_READ)
                try:
                    install_location = winreg.QueryValueEx(subchave, "InstallLocation")[0]
                    if install_location and not os.path.exists(install_location):
                        winreg.CloseKey(subchave)
                        winreg.DeleteKey(chave, subchave_nome)
                        logging.info(f"Entrada órfã removida: {subchave_nome}")
                        removidos += 1
                        i -= 1  # Ajustar índice após remoção
                    else:
                        winreg.CloseKey(subchave)
                except FileNotFoundError:
                    winreg.CloseKey(subchave)
                i += 1
                current += 1
            except OSError:
                break
        winreg.CloseKey(chave)
        return removidos
    except Exception as e:
        logging.error(f"Erro na limpeza de registro: {e}")
        return 0

def executar_desinstalador_oficial(uninstall_string):
    """Executa o desinstalador oficial do programa."""
    if uninstall_string:
        try:
            # Para MSI, ajustar para msiexec
            if "msiexec" in uninstall_string.lower():
                guid_match = re.search(r'\{[A-F0-9-]+\}', uninstall_string, re.IGNORECASE)
                if guid_match:
                    guid = guid_match.group(0)
                    subprocess.run(['msiexec', '/x', guid, '/quiet', '/norestart'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    logging.info(f"Desinstalador MSI executado: {guid}")
                    print(f"Desinstalador MSI executado: {guid}")
                    return True
            else:
                # Executar string diretamente
                subprocess.run(uninstall_string, shell=True, check=True)
                logging.info(f"Desinstalador executado: {uninstall_string}")
                print(f"Desinstalador executado: {uninstall_string}")
                return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao executar desinstalador: {e}")
            print(f"Erro ao executar desinstalador: {e}")
    return False

def matar_processos(programa_nome):
    """Mata processos relacionados ao programa."""
    try:
        result = subprocess.run(['taskkill', '/f', '/t', '/im', f'*{programa_nome}*.exe'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            print(f"Processos relacionados a '{programa_nome}' foram terminados.")
            logging.info(f"Processos relacionados a '{programa_nome}' foram terminados.")
        else:
            print(f"Erro ao terminar processos de '{programa_nome}': {result.stderr}")
            logging.error(f"Erro ao terminar processos de '{programa_nome}': {result.stderr}")
    except Exception as e:
        logging.error(f"Erro ao executar taskkill: {e}")
        print(f"Erro ao executar taskkill: {e}")

def remover_diretorio(caminho):
    """Remove um diretório e seu conteúdo."""
    try:
        if os.path.exists(caminho):
            shutil.rmtree(caminho)
            logging.info(f"Diretório removido: {caminho}")
            print(f"Diretório removido: {caminho}")
        else:
            print(f"Diretório não encontrado: {caminho}")
    except Exception as e:
        logging.error(f"Erro ao remover diretório {caminho}: {e}")
        print(f"Erro ao remover diretório {caminho}: {e}")

def criar_backup(caminho):
    """Cria backup do diretório de instalação."""
    if caminho and os.path.exists(caminho):
        backup_dir = tempfile.mkdtemp(prefix="backup_desinstalador_")
        try:
            shutil.copytree(caminho, os.path.join(backup_dir, os.path.basename(caminho)))
            logging.info(f"Backup criado em: {backup_dir}")
            print(f"Backup criado em: {backup_dir}")
            return backup_dir
        except Exception as e:
            logging.error(f"Erro ao criar backup: {e}")
            print(f"Erro ao criar backup: {e}")
    return None

def limpeza_profunda(callback=None):
    """Realiza limpeza profunda de arquivos temporários e obsoletos."""
    caminhos_temp = [
        os.path.expanduser("~\\AppData\\Local\\Temp"),
        "C:\\Windows\\Temp",
        "C:\\Temp",
        os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\INetCache"),
        os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files"),
        "C:\\Windows\\Prefetch",
        "C:\\Windows\\Logs",
    ]
    total_items = 0
    current = 0
    # Count total
    for caminho in caminhos_temp:
        if os.path.exists(caminho):
            for raiz, dirs, arquivos in os.walk(caminho):
                total_items += len(arquivos)
    # Remove
    removidos = 0
    for caminho in caminhos_temp:
        if os.path.exists(caminho):
            for raiz, dirs, arquivos in os.walk(caminho, topdown=False):
                for arquivo in arquivos:
                    if callback:
                        callback(current, total_items, os.path.join(raiz, arquivo))
                    try:
                        os.remove(os.path.join(raiz, arquivo))
                        removidos += 1
                    except:
                        pass
                    current += 1
                for dir_ in dirs:
                    try:
                        os.rmdir(os.path.join(raiz, dir_))
                    except:
                        pass
    
    # Esvaziar lixeira
    try:
        if callback:
            callback(current, total_items, "Lixeira")
        subprocess.run(['rd', '/s', '/q', 'C:\\$Recycle.Bin'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        removidos += 1
        current += 1
    except Exception as e:
        pass
    
    # Limpar cache de thumbnails
    thumb_cache = os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\Explorer")
    if os.path.exists(thumb_cache):
        for arquivo in os.listdir(thumb_cache):
            if arquivo.startswith("thumbcache"):
                if callback:
                    callback(current, total_items, os.path.join(thumb_cache, arquivo))
                try:
                    os.remove(os.path.join(thumb_cache, arquivo))
                    removidos += 1
                except:
                    pass
                current += 1
    
    return removidos

def varrer_arquivos_residuos_completo(programa_nome):
    """Varre por arquivos residuais em caminhos comuns."""
    caminhos_varredura = [
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Windows",
        os.path.expanduser("~\\AppData"),
    ]
    residuos = []
    for caminho_base in caminhos_varredura:
        if os.path.exists(caminho_base):
            print(f"Varredura em {caminho_base}...")
            for raiz, dirs, arquivos in os.walk(caminho_base):
                for arquivo in arquivos:
                    if programa_nome.lower() in arquivo.lower():
                        caminho_completo = os.path.join(raiz, arquivo)
                        residuos.append(caminho_completo)
    return residuos

def remover_arquivos_residuos(residuos):
    """Remove arquivos residuais encontrados."""
    for arquivo in residuos:
        try:
            os.remove(arquivo)
            logging.info(f"Arquivo residual removido: {arquivo}")
            print(f"Arquivo residual removido: {arquivo}")
        except Exception as e:
            logging.error(f"Erro ao remover arquivo {arquivo}: {e}")
            print(f"Erro ao remover arquivo {arquivo}: {e}")

def scan_suspeitos():
    """Varre por arquivos suspeitos em processos e locais comuns."""
    suspeitos = []
    # Verificar processos
    try:
        result = subprocess.run(['tasklist', '/fo', 'csv'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        for line in result.stdout.splitlines()[1:]:
            parts = line.split(',')
            if len(parts) > 1:
                exe = parts[0].strip('"')
                if any(s in exe.lower() for s in ['temp', 'cache', 'unknown', 'suspicious']):
                    suspeitos.append(f"Processo suspeito: {exe}")
    except:
        pass
    # Verificar arquivos em startup
    startup = os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
    if os.path.exists(startup):
        for arquivo in os.listdir(startup):
            if arquivo.endswith('.exe'):
                suspeitos.append(f"Arquivo em startup: {os.path.join(startup, arquivo)}")
    return suspeitos

def get_cpu():
    try:
        result = subprocess.run(['wmic', 'cpu', 'get', 'loadpercentage'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        lines = result.stdout.strip().split('\n')
        if len(lines) > 1:
            return lines[1].strip()
        return "N/A"
    except:
        return "N/A"

def get_mem():
    try:
        result = subprocess.run(['wmic', 'os', 'get', 'freephysicalmemory,totalvisiblememorysize'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        lines = result.stdout.strip().split('\n')
        if len(lines) > 1:
            parts = lines[1].split()
            free = int(parts[0])
            total = int(parts[1])
            percent = (total - free) / total * 100
            return f"{percent:.1f}"
        return "N/A"
    except:
        return "N/A"

def get_running_processes():
    """Retorna uma lista de processos em execução."""
    try:
        result = subprocess.run(['tasklist', '/fo', 'csv'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        processos = [line.split(',')[0].strip('"') for line in result.stdout.splitlines()[1:] if line.split(',')[0].strip('"')]
        return processos
    except:
        return []
def scan_malware(callback=None):
    """Scan avançado por malware usando hashes e VirusTotal."""
    suspeitos = []
    vt_cache = {}  # Cache para evitar chamadas repetidas
    total_items = 0
    current = 0
    # Verificar processos
    try:
        result = subprocess.run(['tasklist', '/fo', 'csv'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        processos = [line.split(',')[0].strip('"') for line in result.stdout.splitlines()[1:] if line.split(',')[0].strip('"')]
        total_items += len(processos)
        for exe_path in processos:
            if callback:
                callback(current, total_items, exe_path)
            try:
                result2 = subprocess.run(['where', exe_path], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if result2.returncode == 0:
                    caminho = result2.stdout.strip().split('\n')[0]
                    if os.path.exists(caminho):
                        hash_val = calcular_hash_arquivo(caminho)
                        if hash_val and hash_val not in vt_cache:
                            vt_cache[hash_val] = verificar_virustotal(hash_val)
                        malicious, total = vt_cache.get(hash_val, (None, None))
                        if malicious is not None and malicious > 0:
                            suspeitos.append({'tipo': 'processo', 'nome': exe_path, 'caminho': caminho, 'malicious': malicious, 'total': total})
            except:
                pass
            current += 1
    except:
        pass
    # Verificar startup
    startup = os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
    if os.path.exists(startup):
        arquivos_startup = [f for f in os.listdir(startup) if f.endswith('.exe') or f.endswith('.lnk')]
        total_items += len(arquivos_startup)
        for arquivo in arquivos_startup:
            caminho = os.path.join(startup, arquivo)
            if callback:
                callback(current, total_items, caminho)
            hash_val = calcular_hash_arquivo(caminho)
            if hash_val and hash_val not in vt_cache:
                vt_cache[hash_val] = verificar_virustotal(hash_val)
            malicious, total = vt_cache.get(hash_val, (None, None))
            if malicious is not None and malicious > 0:
                suspeitos.append({'tipo': 'arquivo', 'nome': arquivo, 'caminho': caminho, 'malicious': malicious, 'total': total})
            current += 1
    return suspeitos

def gerar_relatorio(programa_nome, oficial_executado, backup_path, residuos):
    """Gera um relatório detalhado da desinstalação."""
    relatorio = f"Relatório de Desinstalação - {programa_nome}\n"
    relatorio += "=" * 50 + "\n"
    relatorio += f"Programa: {programa_nome}\n"
    relatorio += f"Desinstalador oficial executado: {'Sim' if oficial_executado else 'Não'}\n"
    relatorio += f"Backup criado: {backup_path if backup_path else 'Não'}\n"
    relatorio += f"Arquivos residuais encontrados: {len(residuos)}\n"
    if residuos:
        relatorio += "Resíduos:\n"
        for res in residuos:
            relatorio += f"  {res}\n"
    relatorio += "Status: 100% removido e limpo\n" if not residuos else "Status: Resíduos restantes\n"
    
    with open("relatorio_desinstalacao.txt", "w") as f:
        f.write(relatorio)
    print("Relatório gerado: relatorio_desinstalacao.txt")

class DesinstaladorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Desinstalador Completo")
        self.root.geometry("1200x600")
        # Centralizar a janela na tela
        self.root.update_idletasks()
        width = 1200
        height = 600
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.programas = listar_programas_instalados()
        self.processos = get_running_processes()
        self.malware_encontrado = []
        self.criar_widgets()
        self.update_system_info()
        # Start system info update
        threading.Thread(target=self.update_system_info, daemon=True).start()

    def remover_malware_gui(self):
        selecao = self.malware_listbox.curselection()
        if not selecao:
            messagebox.showerror("Erro", "Selecione um item malicioso na aba 'Malware'.")
            return
        self.log_text.delete(1.0, tk.END)
        item = self.malware_encontrado[selecao[0]]
        if item['tipo'] == 'processo':
            if messagebox.askyesno("Remover Malware", f"Matar processo malicioso: {item['nome']}?"):
                try:
                    result = subprocess.run(['taskkill', '/f', '/t', '/im', item['nome']], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    if result.returncode == 0:
                        self.log(f"Processo '{item['nome']}' terminado.")
                    else:
                        self.log(f"Erro ao matar '{item['nome']}': {result.stderr}")
                except Exception as e:
                    self.log(f"Erro ao executar taskkill: {e}")
        elif item['tipo'] == 'arquivo':
            if messagebox.askyesno("Remover Malware", f"Deletar arquivo malicioso: {item['caminho']}?"):
                try:
                    os.remove(item['caminho'])
                    self.log(f"Arquivo '{item['caminho']}' removido.")
                except:
                    self.log(f"Erro ao remover '{item['caminho']}'.")
        # Remover da lista
        self.malware_encontrado.pop(selecao[0])
        self.malware_listbox.delete(selecao[0])

    def matar_processo_gui(self):
        exe = simpledialog.askstring("Matar Processo", "Digite o nome do executável (ex: chrome.exe):")
        if exe:
            try:
                subprocess.run(['taskkill', '/f', '/im', exe], check=True)
                self.log(f"Processo '{exe}' terminado.")
                messagebox.showinfo("Sucesso", f"Processo '{exe}' foi terminado.")
            except subprocess.CalledProcessError:
                self.log(f"Erro ao matar '{exe}'. Processo não encontrado ou sem permissões.")
                messagebox.showerror("Erro", f"Não foi possível matar '{exe}'.")
            except Exception as e:
                self.log(f"Erro inesperado: {e}")
                messagebox.showerror("Erro", f"Erro: {e}")

    def criar_widgets(self):
        # Frames principais
        left_frame = tk.Frame(self.root, width=200, bg='lightgray')
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        right_frame = tk.Frame(self.root)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Botões no lado esquerdo
        tk.Label(left_frame, text="Desinstalação:", bg='lightgray', font=('Arial', 10, 'bold')).pack(pady=2)
        tk.Button(left_frame, text="Desinstalar Selecionado", command=self.desinstalar).pack(fill=tk.X, pady=1)
        tk.Button(left_frame, text="Ver Relatório", command=self.ver_relatorio).pack(fill=tk.X, pady=1)

        tk.Label(left_frame, text="Limpeza:", bg='lightgray', font=('Arial', 10, 'bold')).pack(pady=2)
        tk.Button(left_frame, text="Limpeza Profunda", command=self.limpeza_profunda_gui).pack(fill=tk.X, pady=1)
        tk.Button(left_frame, text="Limpeza de Registro", command=self.limpeza_registro_gui).pack(fill=tk.X, pady=1)

        tk.Label(left_frame, text="Verificação:", bg='lightgray', font=('Arial', 10, 'bold')).pack(pady=2)
        tk.Button(left_frame, text="Scan Suspeitos", command=self.scan_suspeitos_gui).pack(fill=tk.X, pady=1)
        tk.Button(left_frame, text="Scan Malware (VT)", command=self.scan_malware_gui).pack(fill=tk.X, pady=1)
        tk.Button(left_frame, text="Remover Malware", command=self.remover_malware_gui).pack(fill=tk.X, pady=1)

        tk.Label(left_frame, text="Processos:", bg='lightgray', font=('Arial', 10, 'bold')).pack(pady=2)
        tk.Button(left_frame, text="Matar Processo", command=self.matar_processo_gui).pack(fill=tk.X, pady=1)
        tk.Button(left_frame, text="Atualizar Processos", command=self.atualizar_processos).pack(fill=tk.X, pady=1)
        tk.Button(left_frame, text="Atualizar Programas", command=self.atualizar_programas).pack(fill=tk.X, pady=1)

        # Barra de progresso
        self.progress = ttk.Progressbar(left_frame, orient="horizontal", length=180, mode="determinate")
        self.progress.pack(pady=5)
        self.progress_label = tk.Label(left_frame, text="", bg='lightgray', wraplength=180)
        self.progress_label.pack(pady=2)

        # Monitor do sistema
        tk.Label(left_frame, text="Sistema:", bg='lightgray', font=('Arial', 10, 'bold')).pack(pady=2)
        self.cpu_label = tk.Label(left_frame, text="CPU: --%", bg='lightgray')
        self.cpu_label.pack(pady=1)
        self.mem_label = tk.Label(left_frame, text="Memória: --%", bg='lightgray')
        self.mem_label.pack(pady=1)
        self.disk_label = tk.Label(left_frame, text="Armazenamento: --% livre", bg='lightgray')
        self.disk_label.pack(pady=1)

        # Lado direito: abas para programas, processos e malware
        notebook = ttk.Notebook(right_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        # Aba Programas
        program_frame = tk.Frame(notebook)
        notebook.add(program_frame, text="Programas")
        self.program_label = tk.Label(program_frame, text="Programas Instalados:")
        self.program_label.pack(pady=2)
        self.program_listbox = tk.Listbox(program_frame, height=15)
        for chave, nome in self.programas:
            self.program_listbox.insert(tk.END, f"{nome} ({chave})")
        self.program_listbox.pack(fill=tk.BOTH, expand=True)

        # Aba Processos
        process_frame = tk.Frame(notebook)
        notebook.add(process_frame, text="Processos")
        tk.Label(process_frame, text="Processos em Execução:").pack(pady=2)
        self.process_listbox = tk.Listbox(process_frame, height=15)
        for exe in self.processos:
            self.process_listbox.insert(tk.END, exe)
        self.process_listbox.pack(fill=tk.BOTH, expand=True)

        # Aba Malware
        malware_frame = tk.Frame(notebook)
        notebook.add(malware_frame, text="Malware")
        self.malware_label = tk.Label(malware_frame, text="Itens Maliciosos:")
        self.malware_label.pack(pady=2)
        self.malware_listbox = tk.Listbox(malware_frame, height=15)
        self.malware_listbox.pack(fill=tk.BOTH, expand=True)

        # Logs
        tk.Label(right_frame, text="Logs:").pack(pady=5)
        self.log_text = scrolledtext.ScrolledText(right_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def progress_callback(self, current, total, msg):
        self.progress['value'] = (current / total) * 100 if total > 0 else 0
        self.progress_label.config(text=msg)
        self.root.update_idletasks()

    def desinstalar(self):
        selecao = self.program_listbox.curselection()
        if not selecao:
            messagebox.showerror("Erro", "Selecione um programa.")
            return
        programa_chave, programa_nome = self.programas[selecao[0]]
        if not messagebox.askyesno("Confirmar", f"Desinstalar {programa_nome}?"):
            return
        self.log_text.delete(1.0, tk.END)
        self.progress['maximum'] = 10
        self.progress['value'] = 0
        self.log(f"Iniciando desinstalação de '{programa_nome}'...")
        self.root.update_idletasks()
        # Obter info
        self.progress_label.config(text="Obtendo informações...")
        self.log("Obtendo informações de instalação...")
        caminho_programa, uninstall_string = obter_info_instalacao(programa_chave)
        if caminho_programa:
            self.log(f"Local: {caminho_programa}")
        self.progress['value'] += 1
        self.root.update_idletasks()
        # Executar oficial
        self.progress_label.config(text="Executando desinstalador oficial...")
        self.log("Executando desinstalador oficial...")
        oficial = executar_desinstalador_oficial(uninstall_string)
        self.progress['value'] += 1
        self.root.update_idletasks()
        # Backup
        self.progress_label.config(text="Criando backup...")
        self.log("Criando backup...")
        backup = criar_backup(caminho_programa) if not oficial and caminho_programa else None
        self.progress['value'] += 1
        self.root.update_idletasks()
        # Matar processos
        self.progress_label.config(text="Terminando processos...")
        self.log("Terminando processos relacionados...")
        matar_processos(programa_nome)
        self.progress['value'] += 1
        self.root.update_idletasks()
        # Remover dir
        if caminho_programa:
            self.progress_label.config(text="Removendo diretório...")
            self.log("Removendo diretório de instalação...")
            remover_diretorio(caminho_programa)
        self.progress['value'] += 1
        self.root.update_idletasks()
        # Remover reg
        self.progress_label.config(text="Removendo do registro...")
        self.log("Removendo entradas do registro...")
        remover_do_registro(programa_chave)
        self.progress['value'] += 1
        self.root.update_idletasks()
        # Varredura
        self.progress_label.config(text="Varredura por resíduos...")
        self.log("Varredura por arquivos residuais...")
        residuos = varrer_arquivos_residuos_completo(programa_nome)
        self.progress['value'] += 1
        self.root.update_idletasks()
        if residuos:
            if messagebox.askyesno("Resíduos", f"Encontrados {len(residuos)} resíduos. Remover?"):
                self.log("Removendo resíduos...")
                remover_arquivos_residuos(residuos)
                self.log("Resíduos removidos.")
            else:
                self.log("Resíduos não removidos.")
        self.progress['value'] += 1
        self.root.update_idletasks()
        # Relatório
        self.progress_label.config(text="Gerando relatório...")
        self.log("Gerando relatório...")
        gerar_relatorio(programa_nome, oficial, backup, residuos)
        self.progress['value'] += 1
        self.root.update_idletasks()
        self.progress_label.config(text="Concluído")
        self.log("Desinstalação concluída.")

    def ver_relatorio(self):
        if os.path.exists("relatorio_desinstalacao.txt"):
            os.startfile("relatorio_desinstalacao.txt")
        else:
            messagebox.showinfo("Relatório", "Nenhum relatório encontrado. Execute uma desinstalação primeiro.")

    def limpeza_profunda_gui(self):
        if messagebox.askyesno("Limpeza Profunda", "Isso removerá arquivos temporários e obsoletos. Continuar?"):
            self.log_text.delete(1.0, tk.END)
            self.log("Iniciando limpeza profunda...")
            self.progress['maximum'] = 100
            self.progress['value'] = 0
            self.progress_label.config(text="Iniciando limpeza...")
            def run_clean():
                total = limpeza_profunda(self.progress_callback)
                self.root.after(0, lambda: self.finish_clean(total))
            threading.Thread(target=run_clean, daemon=True).start()

    def finish_clean(self, total):
        self.progress['value'] = 100
        self.progress_label.config(text="Limpeza concluída")
        self.log(f"Limpeza concluída: {total} itens removidos.")
        messagebox.showinfo("Limpeza", f"Limpeza concluída: {total} itens removidos.")

    def limpeza_registro_gui(self):
        if messagebox.askyesno("Limpeza de Registro", "Isso removerá entradas órfãs do registro. Pode ser arriscado. Continuar?"):
            self.log_text.delete(1.0, tk.END)
            self.log("Iniciando limpeza de registro...")
            self.progress['maximum'] = 100
            self.progress['value'] = 0
            self.progress_label.config(text="Iniciando limpeza...")
            def run_clean():
                removidos = limpeza_registro(self.progress_callback)
                self.root.after(0, lambda: self.finish_registro(removidos))
            threading.Thread(target=run_clean, daemon=True).start()

    def finish_registro(self, removidos):
        self.progress['value'] = 100
        self.progress_label.config(text="Limpeza concluída")
        self.log(f"Limpeza de registro concluída: {removidos} entradas removidas.")
        messagebox.showinfo("Limpeza de Registro", f"{removidos} entradas órfãs removidas.")

    def scan_suspeitos_gui(self):
        self.log_text.delete(1.0, tk.END)
        self.log("Iniciando scan por suspeitos...")
        suspeitos = scan_suspeitos()
        if suspeitos:
            self.log("Suspeitos encontrados:")
            for s in suspeitos:
                self.log(s)
            messagebox.showwarning("Scan Suspeitos", f"Encontrados {len(suspeitos)} itens suspeitos. Verifique o log.")
        else:
            self.log("Nenhum suspeito encontrado.")
            messagebox.showinfo("Scan Suspeitos", "Nenhum item suspeito encontrado.")

    def scan_malware_gui(self):
        if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "SUA_CHAVE_AQUI":
            messagebox.showerror("Erro", "Defina sua chave da API do VirusTotal no código (VIRUSTOTAL_API_KEY).")
            return
        self.log_text.delete(1.0, tk.END)
        self.log("Iniciando scan avançado por malware...")
        self.progress['maximum'] = 100
        self.progress['value'] = 0
        self.progress_label.config(text="Iniciando varredura...")
        def run_scan():
            malware = scan_malware(self.progress_callback)
            self.root.after(0, lambda: self.finish_scan(malware))
        threading.Thread(target=run_scan, daemon=True).start()

    def finish_scan(self, malware):
        self.progress['value'] = 100
        self.progress_label.config(text="Scan concluído")
        self.malware_encontrado = malware
        self.malware_listbox.delete(0, tk.END)
        if malware:
            for item in malware:
                self.malware_listbox.insert(tk.END, f"{item['tipo'].capitalize()}: {item['nome']} - {item['malicious']}/{item['total']} engines")
            self.log(f"Encontrados {len(malware)} itens maliciosos.")
            messagebox.showwarning("Scan Malware", f"Encontrados {len(malware)} itens maliciosos. Verifique a aba 'Malware'.")
        else:
            self.malware_listbox.insert(tk.END, "Nenhum malware encontrado.")
            self.log("Nenhum malware encontrado.")
            messagebox.showinfo("Scan Malware", "Nenhum malware encontrado.")

    def atualizar_programas(self):
        self.programas = listar_programas_instalados()
        self.program_listbox.delete(0, tk.END)
        for chave, nome in self.programas:
            self.program_listbox.insert(tk.END, f"{nome} ({chave})")
        self.log("Lista de programas atualizada.")

    def matar_processo_gui(self):
        selecao = self.process_listbox.curselection()
        if not selecao:
            messagebox.showerror("Erro", "Selecione um processo.")
            return
        processo = self.processos[selecao[0]]
        if messagebox.askyesno("Matar Processo", f"Matar {processo}?"):
            try:
                result = subprocess.run(['taskkill', '/f', '/t', '/im', processo], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    self.log(f"Processo '{processo}' terminado com sucesso.")
                    messagebox.showinfo("Sucesso", f"Processo '{processo}' foi terminado.")
                    self.atualizar_processos()
                else:
                    self.log(f"Erro ao terminar '{processo}': {result.stderr}")
                    messagebox.showerror("Erro", f"Não foi possível terminar o processo '{processo}'.\nErro: {result.stderr}")
            except Exception as e:
                self.log(f"Erro ao executar taskkill: {e}")
                messagebox.showerror("Erro", f"Erro ao executar comando: {e}")

    def atualizar_processos(self):
        self.processos = get_running_processes()
        self.process_listbox.delete(0, tk.END)
        for exe in self.processos:
            self.process_listbox.insert(tk.END, exe)
        self.log("Lista de processos atualizada.")

    def update_system_info(self):
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').free / psutil.disk_usage('/').total * 100
            self.cpu_label.config(text=f"CPU: {cpu:.1f}%")
            self.mem_label.config(text=f"Memória: {mem:.1f}%")
            self.disk_label.config(text=f"Armazenamento: {disk:.1f}% livre")
        except Exception as e:
            self.cpu_label.config(text="CPU: N/A")
            self.mem_label.config(text="Memória: N/A")
            self.disk_label.config(text="Armazenamento: N/A")
        self.root.after(2000, self.update_system_info)

def main():
    try:
        root = tk.Tk()
        # Tentar carregar ícone de URL externa
        try:
            url = "https://img.icons8.com/color/48/000000/uninstall.png"  # Substitua pela URL desejada (PNG)
            with urllib.request.urlopen(url) as u:
                raw_data = u.read()
            image = Image.open(io.BytesIO(raw_data))
            # Salvar como ICO temporário para usar com iconbitmap
            temp_icon = tempfile.NamedTemporaryFile(delete=False, suffix='.ico')
            temp_icon.close()  # Fechar para salvar
            image.save(temp_icon.name, format='ICO')
            root.iconbitmap(temp_icon.name)
            # Nota: o arquivo temp fica até o fim da execução
        except:
            # Fallback para ícone local ou padrão
            try:
                root.iconbitmap('icon.ico')
            except:
                pass
        app = DesinstaladorGUI(root)
        root.lift()
        root.focus_force()
        root.attributes('-topmost', True)
        root.after(100, lambda: root.attributes('-topmost', False))
        root.mainloop()
    except Exception as e:
        print(f"Erro: {e}")
        import traceback
        traceback.print_exc()
        input("Pressione Enter para sair")

if __name__ == "__main__":
    main()
