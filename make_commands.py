import xml.etree.ElementTree as ET
import os

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



def merge_oval_files(file_paths, output_path="CVE.FSTEK.xml"):
    if not file_paths:
        print("Список файлов пуст.")
        return

    base_tree = ET.parse(file_paths[0])
    base_root = base_tree.getroot()
    new_root = ET.Element(base_root.tag, attrib=base_root.attrib)
    new_tree = ET.ElementTree(new_root)

    for generator in base_root.findall('{http://oval.mitre.org/XMLSchema/oval-definitions-5}generator'):
        new_root.append(generator)

    added_definitions = set()
    for file_path in file_paths:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for definition in root.findall('{http://oval.mitre.org/XMLSchema/oval-definitions-5}definitions'):
            for child in definition:
                def_id = child.get('id')
                if def_id not in added_definitions:
                    new_root.append(child)
                    added_definitions.add(def_id)

    new_tree.write(output_path)

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
            if counter % 30000 == 0:
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
