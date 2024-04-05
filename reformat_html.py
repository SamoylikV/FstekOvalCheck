from main import reformat_html, execute_command
import os
import colorlog
import logging

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
logger.info("Оценка завершена.")
logger.info("Удаление временных файлов...")
fstek_string = 'FSTEK'
path = os.path.dirname(os.path.realpath(__file__))
for file in os.listdir(path):
    if fstek_string in file.split('.'):
        execute_command(f"rm -rf {file}")
logger.info("Файлы CVE.FSTEK.xml удалены.")
logger.info("реформатирование HTML файла...")
reformat_html('vullist.xlsx', 'report.html')
logger.info("HTML файл переформатирован.")
execute_command(f"rm {os.path.join(path, 'oval_make.command')}")
execute_command(f"rm {os.path.join(path, 'export.xml')}")
execute_command(f"rm {os.path.join(path, 'vullist.xlsx')}")
execute_command(f"rm -rf {os.path.join(path, 'report.html')}")
execute_command(f"rm -rf {os.path.join(path, 'OVALRepo')}")
logger.info("Все временные файлы удалены.")


