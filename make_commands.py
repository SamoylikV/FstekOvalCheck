import xml.etree.ElementTree as ET
import os
from lxml import etree
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_cve_ids_from_export(export_file_path):
    logging.info(f"Начинаем извлечение идентификаторов CVE из {export_file_path}")
    cve_ids = set()
    try:
        tree = ET.parse(export_file_path)
        root = tree.getroot()
        identifiers = root.findall('.//identifier')
        for identifier in identifiers:
            if identifier.get('type') == "CVE":
                cve_ids.add(identifier.text)
        logging.info(f"Успешно извлечено {len(cve_ids)} идентификаторов CVE.")
    except ET.ParseError as e:
        logging.error(f"Ошибка при разборе XML: {e}")
    except Exception as e:
        logging.error(f"Произошла ошибка: {e}")
    return list(cve_ids)

def merge_oval_files(files_list, output_file_path="CVE.FSTEK.xml"):
    logging.info("Начинаем слияние OVAL файлов...")
    if not files_list or len(files_list) < 2:
        logging.warning("Для слияния требуется минимум два файла.")
        return
    tree1 = etree.parse(files_list[0])
    root1 = tree1.getroot()
    for file_path in files_list[1:]:
        logging.info(f"Обработка файла {file_path}")
        tree = etree.parse(file_path)
        vulnerabilities = tree.xpath('//vulnerability')
        for vulnerability in vulnerabilities:
            root1.append(vulnerability)
    tree1.write(output_file_path, pretty_print=True, xml_declaration=True, encoding="UTF-8")
    logging.info(f"Файлы успешно объединены и сохранены в {output_file_path}")
    return files_list[1:]

def make_commands(export_file_path):
    logging.info(f"Начинаем создание команд для экспорта CVE из {export_file_path}")
    cve_ids = get_cve_ids_from_export(export_file_path)
    cve_ids_final = []
    for cve_id in cve_ids:
        if cve_id.startswith("CVE") and len(cve_id.split('-')[1]) == 4 and len(cve_id.split('-')[2]) >= 4:
            cve_ids_final.append(cve_id)
    logging.info(f"Отфильтровано {len(cve_ids_final)} подходящих идентификаторов CVE.")
    counter = 0
    counter2 = 1
    files = []
    with open('oval_make.command', 'w') as file:
        logging.info("Начинаем запись команд в файл.")
        for cve_id in cve_ids_final:
            counter += 1
            if counter % 5000 == 0:
                counter2 += 1
                files.append(f"CVE.FSTEK{counter2}.xml")
                file.write("\n")
                logging.info(f"Создание команды для файла CVE.FSTEK{counter2}.xml")
                file.write(f"python3 {os.path.dirname(os.path.realpath(__file__))}/OVALRepo/scripts/build_oval_definitions_file.py -o {os.path.dirname(os.path.realpath(__file__))}/CVE.FSTEK{counter2}.xml --family unix --reference_id ")
            elif counter == 1:
                files.append(f"CVE.FSTEK{counter2}.xml")
                logging.info("Создание начальной команды для экспорта.")
                file.write(f"python3 {os.path.dirname(os.path.realpath(__file__))}/OVALRepo/scripts/build_oval_definitions_file.py -o {os.path.dirname(os.path.realpath(__file__))}/CVE.FSTEK{counter2}.xml --family unix --reference_id ")
            file.write(f'"{cve_id}" ')
    logging.info("Команды успешно записаны.")
    return files, f"{os.path.dirname(os.path.realpath(__file__))}"
