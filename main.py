from make_commands import make_commands, merge_oval_files
import subprocess

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

files, path = make_commands('export.xml')

with open("oval_make.command", 'r') as file:
    commands = file.readlines()

execute_command(f"git clone git clone https://github.com/CISecurity/OVALRepo.git {path}")
try:
    execute_command(f"pip install -r {path}/OVALRepo/scripts/requirements.txt")
except Exception:
    execute_command(f"pip3 install -r {path}/OVALRepo/scripts/requirements.txt")
for command in commands:
    command = command.strip()
    if command:
        execute_command(command)


# merge_oval_files(files)
