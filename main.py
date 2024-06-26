import subprocess
import logging
import xml.etree.ElementTree as ET
import os
from lxml import etree
import colorlog
import pandas as pd
import re
from bs4 import BeautifulSoup


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
            if identifier.text.startswith("CVE"):
                cve_ids.add(identifier.text)
        logger.info(f"Успешно извлечено {len(cve_ids)} идентификаторов CVE.")
    except ET.ParseError as e:
        logger.error(f"Ошибка при разборе XML: {e}")
    except Exception as e:
        logger.error(f"Произошла ошибка: {e}")
    return list(cve_ids)

def get_bdu_ids_from_export(xlsx_file_path, cve_ids):
    columns = ['Идентификатор BDU', 'Наименование уязвимости', 'Описание уязвимости', 'Вендор ПО', 'Название ПО',
               'Версия ПО', 'Тип ПО', 'Описание', 'Дата обнаружения', 'Дата устранения', 'Способ устранения',
               'Официальное подтверждение', 'Дата последнего подтверждения', 'Описание мер устранения',
               'Статус уязвимости', 'Наличие эксплойта', 'Информация об устранении', 'Ссылки на источники',
               'Идентификаторы других систем описаний уязвимости', 'Прочая информация', 'Связь с инцидентами ИБ',
               'Описание ошибки CWE', 'Тип ошибки CWE']
    data_cleaned = pd.read_excel(xlsx_file_path, skiprows=2, names=columns)
    data_bdu_cve = data_cleaned[['Идентификатор BDU', 'Идентификаторы других систем описаний уязвимости']]
    cve_bdu_mapping = {}
    for _, row in data_bdu_cve.iterrows():
        cves = str(row['Идентификаторы других систем описаний уязвимости']).split(', ')
        for cve in cves:
            if cve.startswith("CVE"):
                if cve in cve_bdu_mapping:
                    cve_bdu_mapping[cve].append(row['Идентификатор BDU'])
                else:
                    cve_bdu_mapping[cve] = [row['Идентификатор BDU']]
    results = {}
    for cve in cve_ids:
        if cve in cve_bdu_mapping:
            results[cve] = cve_bdu_mapping[cve]
    return results


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


def find_bdu_for_cve_fast(cve_list, cve_bdu_mapping):
    results = {}
    for cve in cve_list:
        if cve in cve_bdu_mapping:
            results[cve] = cve_bdu_mapping[cve]
    return results


def reformat_html(xlsx_file_path, html_file_path):

    columns = ['Идентификатор BDU', 'Наименование уязвимости', 'Описание уязвимости', 'Вендор ПО', 'Название ПО',
               'Версия ПО', 'Тип ПО', 'Описание', 'Дата обнаружения', 'Дата устранения', 'Способ устранения',
               'Официальное подтверждение', 'Дата последнего подтверждения', 'Описание мер устранения',
               'Статус уязвимости', 'Наличие эксплойта', 'Информация об устранении', 'Ссылки на источники',
               'Идентификаторы других систем описаний уязвимости', 'Прочая информация', 'Связь с инцидентами ИБ',
               'Описание ошибки CWE', 'Тип ошибки CWE']
    data_cleaned = pd.read_excel(xlsx_file_path, skiprows=2, names=columns)

    data_bdu_cve = data_cleaned[['Идентификатор BDU', 'Идентификаторы других систем описаний уязвимости']]

    cve_bdu_mapping = {}
    for _, row in data_bdu_cve.iterrows():
        cves = str(row['Идентификаторы других систем описаний уязвимости']).split(', ')
        for cve in cves:
            if cve.startswith("CVE"):
                if cve in cve_bdu_mapping:
                    cve_bdu_mapping[cve].append(row['Идентификатор BDU'])
                else:
                    cve_bdu_mapping[cve] = [row['Идентификатор BDU']]

    with open(html_file_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    soup = BeautifulSoup(html_content, 'html.parser')

    for tr in soup.find_all('tr'):
        td_elements = tr.find_all('td', class_='Text', string=lambda text: text and 'inventory' in text.lower())
        if td_elements:
            tr.decompose()

    cve_ids = set()
    for link in soup.find_all('a', href=True):
        if "cve.mitre.org" in link['href']:
            cve_id = re.search(r'CVE-\d{4}-\d{4,7}', link.text)
            if cve_id:
                cve_ids.add(cve_id.group())

    results = find_bdu_for_cve_fast(cve_ids, cve_bdu_mapping)

    for link in soup.find_all('a', href=True):
        if "cve.mitre.org" in link['href']:
            cve_id = re.search(r'CVE-\d{4}-\d{4,7}', link.text)
            if cve_id and cve_id.group() in results:
                bdu_id = results[cve_id.group()]
                bdu_link = soup.new_tag('span')
                bdu_link.string = f" BDU: {bdu_id}"
                link.insert_after(bdu_link)

    with open('modified_html_file.html', 'w', encoding='utf-8') as file:
        file.write(str(soup.prettify()))


def main():
    logger.info("Загрузка файла экспорта...")
    execute_command(
        f"wget -P {os.path.dirname(os.path.realpath(__file__))} https://bdu.fstec.ru/files/documents/vulxml.zip --no-check-certificate")
    execute_command(
        f"wget -P {os.path.dirname(os.path.realpath(__file__))} https://bdu.fstec.ru/files/documents/vullist.xlsx --no-check-certificate")
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

    logger.info("Выполнение оценки уязвимостей...")



if __name__ == "__main__":
    main()
