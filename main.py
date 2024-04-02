import subprocess
import logging
import xml.etree.ElementTree as ET
import os
from lxml import etree
import colorlog

handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    '%(asctime)s - %(log_color)s%(levelname)s%(reset)s - %(message)s',
    datefmt=None,
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%'
))

logger = colorlog.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)


def get_cve_ids_from_export(export_file_path):
    logger.info(f"Начинаем извлечение идентификаторов CVE из {export_file_path}")
    cve_ids = set()
    try:
        tree = ET.parse(export_file_path)
        root = tree.getroot()
        identifiers = root.findall('.//identifier')
        for identifier in identifiers:
            if identifier.get('type') == "CVE":
                cve_ids.add(identifier.text)
        logger.info(f"Успешно извлечено {len(cve_ids)} идентификаторов CVE.")
    except ET.ParseError as e:
        logger.error(f"Ошибка при разборе XML: {e}")
    except Exception as e:
        logger.error(f"Произошла ошибка: {e}")
    return list(cve_ids)


def merge_oval_files(files_list, output_file_path="CVE.FSTEK.xml"):
    logger.info("Начинаем слияние OVAL файлов...")
    if not files_list or len(files_list) < 2:
        logger.warning("Для слияния требуется минимум два файла.")
        return
    tree1 = etree.parse(files_list[0])
    root1 = tree1.getroot()
    for file_path in files_list[1:]:
        logger.info(f"Обработка файла {file_path}")
        tree = etree.parse(file_path)
        vulnerabilities = tree.xpath('//vulnerability')
        for vulnerability in vulnerabilities:
            root1.append(vulnerability)
    tree1.write(output_file_path, pretty_print=True, xml_declaration=True, encoding="UTF-8")
    logger.info(f"Файлы успешно объединены и сохранены в {output_file_path}")
    return files_list[1:]


def make_commands(export_file_path):
    logger.info(f"Начинаем создание команд для экспорта CVE из {export_file_path}")
    cve_ids = get_cve_ids_from_export(export_file_path)
    cve_ids_final = []
    for cve_id in cve_ids:
        if cve_id.startswith("CVE") and len(cve_id.split('-')[1]) == 4 and len(cve_id.split('-')[2]) >= 4:
            cve_ids_final.append(cve_id)
    logger.info(f"Отфильтровано {len(cve_ids_final)} подходящих идентификаторов CVE.")
    counter = 0
    counter2 = 1
    files = []
    with open('oval_make.command', 'w') as file:
        logger.info("Начинаем запись команд в файл.")
        for cve_id in cve_ids_final:
            counter += 1
            if counter % 5000 == 0:
                counter2 += 1
                files.append(f"CVE.FSTEK{counter2}.xml")
                file.write("\n")
                logger.info(f"Создание команды для файла CVE.FSTEK{counter2}.xml")
                file.write(
                    f"python3 {os.path.dirname(os.path.realpath(__file__))}/OVALRepo/scripts/build_oval_definitions_file.py -o {os.path.dirname(os.path.realpath(__file__))}/CVE.FSTEK{counter2}.xml --family unix --reference_id ")
            elif counter == 1:
                files.append(f"CVE.FSTEK{counter2}.xml")
                logger.info("Создание начальной команды для экспорта.")
                file.write(
                    f"python3 {os.path.dirname(os.path.realpath(__file__))}/OVALRepo/scripts/build_oval_definitions_file.py -o {os.path.dirname(os.path.realpath(__file__))}/CVE.FSTEK{counter2}.xml --family unix --reference_id ")
            file.write(f'"{cve_id}" ')
    logger.info("Команды успешно записаны.")
    return files, f"{os.path.dirname(os.path.realpath(__file__))}"


def execute_command(command):
    if len(command) > 100:
        logger.info(f"Выполнение команды: {command[:100]}...")
    else:
        logger.info(f"Выполнение команды: {command}")
    with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            logger.info(line.strip())
        process.wait()
        if process.returncode != 0:
            logger.error(f"Ошибки выполнения команды:")
            for line in process.stderr:
                logger.error(line.strip())
            logger.error(f"Команда '{command}' завершилась с кодом {process.returncode}")
            return process.returncode
    return 0


def main():
    logger.info("Загрузка файла экспорта...")
    execute_command(
        f"wget -P {os.path.dirname(os.path.realpath(__file__))} https://bdu.fstec.ru/files/documents/vulxml.zip --no-check-certificate")
    execute_command(
        f"unzip {os.path.dirname(os.path.realpath(__file__))}/vulxml.zip -d {os.path.dirname(os.path.realpath(__file__))}/")
    execute_command(
        f"mv  {os.path.dirname(os.path.realpath(__file__))}/export/export.xml {os.path.dirname(os.path.realpath(__file__))}/export.xml")
    execute_command(
        f"rm -rf {os.path.dirname(os.path.realpath(__file__))}/export {os.path.dirname(os.path.realpath(__file__))}/vulxml.zip")
    logger.info("Файл экспорта загружен и перемещен.")
    files, path = make_commands('export.xml')
    with open("oval_make.command", 'r') as file:
        commands = file.readlines()
    repo_path = os.path.join(path, "OVALRepo")
    if not os.path.exists(repo_path):
        execute_command(f"git clone https://github.com/CISecurity/OVALRepo.git {repo_path}")
    else:
        logger.info(f"Репозиторий уже существует в {repo_path}, клонирование не требуется.")
    logger.info("Установка зависимостей...")
    if execute_command(f"pip install -r {path}/OVALRepo/scripts/requirements.txt") != 0:
        execute_command(f"pip3 install -r {path}/OVALRepo/scripts/requirements.txt")
    logger.info("Зависимости успешно установлены.")
    for command in commands:
        command = command.strip()
        if command:
            execute_command(command)

    merge_oval_files(files)

    # logger.info("Выполнение оценки уязвимостей...")
    # execute_command(
    #     f"oscap oval eval --results {os.path.join(path, 'results.xml')} --report report.html {os.path.join(path, 'CVE.FSTEK.xml')}")
    # logger.info("Оценка завершена.")
    logger.info("Удаление временных файлов...")
    for file in files:
        execute_command(f"rm {file}")
    execute_command(f"rm {os.path.join(path, 'oval_make.command')}")
    execute_command(f"rm {os.path.join(path, 'export.xml')}")
    execute_command(f"rm -rf {os.path.join(path, 'OVALRepo')}")
    logger.info("Все временные файлы удалены.")


if __name__ == "__main__":
    main()
