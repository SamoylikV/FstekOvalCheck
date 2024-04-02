from make_commands import make_commands, merge_oval_files
import subprocess
import os


def execute_command(command):
    with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            print(line, end='')
        process.wait()
        if process.returncode != 0:
            print(f"Ошибки выполнения команды:")
            for line in process.stderr:
                print(line, end='')

            print(f"Команда '{command}' завершилась с кодом {process.returncode}")


execute_command(
    f"wget -P {os.path.dirname(os.path.realpath(__file__))} https://bdu.fstec.ru/files/documents/vulxml.zip --no-check-certificate")
execute_command(
    f"unzip {os.path.dirname(os.path.realpath(__file__))}/vulxml.zip -d {os.path.dirname(os.path.realpath(__file__))}/")
files, path = make_commands('export.xml')

with open("oval_make.command", 'r') as file:
    commands = file.readlines()
try:
    execute_command(f"cd {path}/OVALRepo")
except:
    execute_command(f"git clone https://github.com/CISecurity/OVALRepo.git {path}/OVALRepo")
try:
    execute_command(f"pip install -r {path}/OVALRepo/scripts/requirements.txt")
except:
    execute_command(f"pip3 install -r {path}/OVALRepo/scripts/requirements.txt")

for command in commands:
    command = command.strip()
    if command:
        execute_command(command)

merge_oval_files(files)
for file in files:
    execute_command(f"rm {file}")