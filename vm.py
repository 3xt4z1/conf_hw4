import sys
import xml.etree.ElementTree as ET

# Код операций и размеры команд
OPCODES = {
    'LOADC': 1,  # Загрузка константы (4 байта)
    'SGN': 3,  # Унарная операция sgn() (3 байта)
    'LOAD': 4,  # Чтение из памяти со смещением (1 байт)
    'STORE': 5  # Запись в память по адресу (3 байта)
}


def assemble_line(line):
    # Удаляем комментарии и лишние пробелы
    line = line.split(';')[0].strip()
    if not line:
        return None, None, None

    parts = line.split()
    mnemonic = parts[0].upper()

    if mnemonic not in OPCODES:
        raise ValueError(f"Неизвестная команда: {mnemonic}")
    A = OPCODES[mnemonic]

    # В зависимости от команды парсим операнд(ы)
    # Формат для каждой команды взят из условия задачи.
    if mnemonic == 'LOADC':
        # 4 байта: A=1 (3 бита), B=константа (23 бита)
        # parts[1] - константа
        B = int(parts[1])
        # Формируем 4 байта
        # Биты: [0..2]=A, [3..25]=B
        # Сдвигаем A в младшие 3 бита, затем добавляем B << 3
        val = (B << 3) | A
        # val занимает 26 бит, нам нужны 4 байта = 32 бита
        # Разложим на байты
        b0 = val & 0xFF
        b1 = (val >> 8) & 0xFF
        b2 = (val >> 16) & 0xFF
        b3 = (val >> 24) & 0xFF
        machine_code = bytes([b0, b1, b2, b3])
        return mnemonic, B, machine_code

    elif mnemonic == 'LOAD':
        # 1 байт: A=4, B=смещение (5 бит)
        B = int(parts[1])
        # val = (B << 3) | A, умещается в 1 байт
        val = (B << 3) | A
        machine_code = bytes([val])
        return mnemonic, B, machine_code

    elif mnemonic == 'STORE':
        # 3 байта: A=5, B=адрес (21 бит)
        B = int(parts[1])
        val = (B << 3) | A
        b0 = val & 0xFF
        b1 = (val >> 8) & 0xFF
        b2 = (val >> 16) & 0xFF
        machine_code = bytes([b0, b1, b2])
        return mnemonic, B, machine_code

    elif mnemonic == 'SGN':
        # 3 байта: A=3, B=адрес (21 бит)
        B = int(parts[1])
        val = (B << 3) | A
        b0 = val & 0xFF
        b1 = (val >> 8) & 0xFF
        b2 = (val >> 16) & 0xFF
        machine_code = bytes([b0, b1, b2])
        return mnemonic, B, machine_code


def assemble(in_path, out_path, log_path):
    # Читаем ассемблерный файл
    with open(in_path, 'r') as f:
        lines = f.readlines()

    machine_code = bytearray()
    root = ET.Element('log')

    for line in lines:
        mnemonic, B, code = assemble_line(line)
        if mnemonic is None:
            continue
        # Добавляем в лог
        instr_el = ET.SubElement(root, 'instruction')
        ET.SubElement(instr_el, 'mnemonic').text = mnemonic
        if B is not None:
            ET.SubElement(instr_el, 'B').text = str(B)
        ET.SubElement(instr_el, 'machine_code').text = ' '.join([f'0x{x:02X}' for x in code])

        machine_code.extend(code)

    # Записываем бинарный файл
    with open(out_path, 'wb') as f:
        f.write(machine_code)

    # Записываем лог в XML
    tree = ET.ElementTree(root)
    tree.write(log_path, encoding='utf-8', xml_declaration=True)


# Пример вызова ассемблера:
# assemble('program.asm', 'program.bin', 'log.xml')


### Часть 2: Интерпретатор

def sgn(x):
    if x < 0:
        return -1
    elif x > 0:
        return 1
    else:
        return 0


def interpret(in_path, out_path, mem_start, mem_end):
    # Инициализируем память, аккумулятор, IP
    memory = [0] * 1024  # условный размер памяти
    acc = 0
    ip = 0

    # В реальных условиях, возможно, память надо инициализировать
    # начальными значениями. Для теста предположим:
    memory[0] = -5
    memory[1] = 0
    memory[2] = 10
    memory[3] = -1

    # Читаем машинный код
    with open(in_path, 'rb') as f:
        code = f.read()

    code_len = len(code)

    while ip < code_len:
        # Читаем следующий опкод
        byte0 = code[ip]
        A = byte0 & 0x07  # Младшие 3 бита - A
        if A == 1:
            # LOADC (4 байта)
            # Bits: [3..25] - B
            if ip + 4 > code_len:
                break
            b0, b1, b2, b3 = code[ip:ip + 4]
            val = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
            # Выделяем B:
            # val = (B << 3) | A  => B = val >> 3
            B = val >> 3
            acc = B
            ip += 4
        elif A == 3:
            # SGN (3 байта)
            if ip + 3 > code_len:
                break
            b0, b1, b2 = code[ip:ip + 3]
            val = (b2 << 16) | (b1 << 8) | b0
            B = val >> 3
            acc = sgn(memory[B])
            ip += 3
        elif A == 4:
            # LOAD (1 байт)
            if ip + 1 > code_len:
                break
            b0 = code[ip]
            B = b0 >> 3
            acc = memory[acc + B]
            ip += 1
        elif A == 5:
            # STORE (3 байта)
            if ip + 3 > code_len:
                break
            b0, b1, b2 = code[ip:ip + 3]
            val = (b2 << 16) | (b1 << 8) | b0
            B = val >> 3
            memory[B] = acc
            ip += 3
        else:
            # Неизвестная или неописанная команда
            # Для простоты выходим
            break

    # По завершении - сохраним диапазон памяти
    root = ET.Element('memory_dump')
    for addr in range(mem_start, mem_end + 1):
        cell_el = ET.SubElement(root, 'cell', address=str(addr))
        cell_el.text = str(memory[addr])
    tree = ET.ElementTree(root)
    tree.write(out_path, encoding='utf-8', xml_declaration=True)


if __name__ == "__main__":
    # Сборка программы
    assemble('program.asm', 'program.bin', 'log.xml')

    # Выполнение программы
    interpret('program.bin', 'result.xml', 0, 3)
