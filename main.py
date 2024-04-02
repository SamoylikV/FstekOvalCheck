from make_commands import make_commands, merge_oval_files
import subprocess
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def execute_command(command):
    logging.info(f"Выполнение команды: {command}")
    with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            logging.info(line.strip())
        process.wait()
        if process.returncode != 0:
            logging.error(f"Ошибки выполнения команды:")
            for line in process.stderr:
                logging.error(line.strip())
            logging.error(f"Команда '{command}' завершилась с кодом {process.returncode}")
            return process.returncode
    return 0

execute_command(
    f"wget -P {os.path.dirname(os.path.realpath(__file__))} https://bdu.fstec.ru/files/documents/vulxml.zip --no-check-certificate")
execute_command(
    f"unzip {os.path.dirname(os.path.realpath(__file__))}/vulxml.zip -d {os.path.dirname(os.path.realpath(__file__))}/")
execute_command(
    f"mv  {os.path.dirname(os.path.realpath(__file__))}/export/export.xml {os.path.dirname(os.path.realpath(__file__))}/export.xml")
execute_command(
    f"rm -rf {os.path.dirname(os.path.realpath(__file__))}/export {os.path.dirname(os.path.realpath(__file__))}/vulxml.zip")

files, path = make_commands('export.xml')
with open("oval_make.command", 'r') as file:
    commands = file.readlines()

repo_path = os.path.join(path, "OVALRepo")
if not os.path.exists(repo_path):
    execute_command(f"git clone https://github.com/CISecurity/OVALRepo.git {repo_path}")
else:
    logging.info(f"Репозиторий уже существует в {repo_path}, клонирование не требуется.")

if execute_command(f"pip install -r {path}/OVALRepo/scripts/requirements.txt") != 0:
    execute_command(f"pip3 install -r {path}/OVALRepo/scripts/requirements.txt")

for command in commands:
    command = command.strip()
    if command:
        execute_command(command)

merge_oval_files(files)
for file in files:
    execute_command(f"rm {file}")
