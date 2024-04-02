import xml.etree.ElementTree as ET
import os
from lxml import etree

BASE_DIR = "cves"


def get_cve_ids_from_export(export_file_path):
    cve_ids = set()
    try:
        tree = ET.parse(export_file_path)
        root = tree.getroot()
        identifiers = root.findall('.//identifier')
        for identifier in identifiers:
            if identifier.get('type') == "CVE":
                cve_ids.add(identifier.text)
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    return list(cve_ids)


def merge_oval_files(files_list, output_file_path="CVE.FSTEK.xml"):
    if not files_list or len(files_list) < 2:
        print("Нужно минимум два файла для слияния")
        return
    tree1 = etree.parse(files_list[0])
    root1 = tree1.getroot()
    for file_path in files_list[1:]:
        tree = etree.parse(file_path)
        vulnerabilities = tree.xpath('//vulnerability')
        for vulnerability in vulnerabilities:
            root1.append(vulnerability)
    tree1.write(output_file_path, pretty_print=True, xml_declaration=True, encoding="UTF-8")
    return files_list[1:]


def make_commands(export_file_path):
    cve_ids = get_cve_ids_from_export(export_file_path)
    cve_ids_final = []
    for cve_id in cve_ids:
        if cve_id.split('-')[0] == "CVE" and len(cve_id.split('-')[1]) == 4 and len(cve_id.split('-')[2]) >= 4:
            cve_ids_final.append(cve_id)
    counter = 0
    counter2 = 1
    files = []
    with open('oval_make.command', 'w') as file:
        for cve_id in cve_ids_final:
            counter += 1
            if counter % 5000 == 0:
                counter2 += 1
                files.append(f"CVE.FSTEK{counter2}.xml")
                file.write("\n")
                file.write(
                    f"python3 {os.path.dirname(os.path.realpath(__file__))}/OVALRepo/scripts/build_oval_definitions_file.py -o {os.path.dirname(os.path.realpath(__file__))}/CVE.FSTEK{counter2}.xml --family unix --reference_id ")
            elif counter == 1:
                files.append(f"CVE.FSTEK{counter2}.xml")
                file.write(
                    f"python3 {os.path.dirname(os.path.realpath(__file__))}/OVALRepo/scripts/build_oval_definitions_file.py -o {os.path.dirname(os.path.realpath(__file__))}/CVE.FSTEK{counter2}.xml --family unix --reference_id ")
            file.write(f'"{cve_id}" ')
    return files, f"{os.path.dirname(os.path.realpath(__file__))}"
