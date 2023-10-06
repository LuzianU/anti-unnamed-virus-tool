import os
import shutil
import struct
import sys
import winreg
import pefile
import argparse
from pyuac import main_requires_admin

def read_bytes(file_path, location, n):
    with open(file_path, "rb") as file:
        file.seek(location)
        data = file.read(n)
        return data

def bytes_to_int32(byte_data):
    return struct.unpack("<i", byte_data)[0]

VIRUS_ENTRY_BYTES = bytes([
	0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x6C, 0x01, 0x00, 
    0x00, 0x33, 0xC0, 0x53, 0x56, 0x57, 0x89, 0x45, 
    0xDC, 0x89, 0x45, 0xF0, 0x89, 0x45, 0xEC, 0x89,
	0x45, 0xF8, 0x89, 0x45, 0xF4, 0x89, 0x45, 0xE0
])

VIRUS_CHARACTERISTICS = 0x0E0000020;

def remove_virus(pe, exe_path):
    address_of_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint # type: ignore
    entry_point_virus_file_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint) # type: ignore 

    # This is where the relative entry point of the original .exe is saved
    data = read_bytes(exe_path, entry_point_virus_file_offset + 0x65, 4)
    data_int = bytes_to_int32(data)

    # relative jump to figure out the where the absolute entry point is
    new_entry_point = address_of_entry_point + 0x26C + data_int + 5
    
    # visualized = " ".join("{:02x}".format(x) for x in struct.pack("<I", new_entry_point))
    # print("new_entry_point:", hex(new_entry_point), "(" + visualized+ ")") 
    
    # Modify the entry point in the optional PE header
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point # type: ignore 
    virus_img_section = pe.sections[-1]
    virus_img_section_file_offset = virus_img_section.get_file_offset()
    
    # Remove the virus image section
    pe.FILE_HEADER.NumberOfSections = pe.FILE_HEADER.NumberOfSections - 1 # type: ignore
    pe.sections = pe.sections[0:-1]
    
    last_img_section = pe.sections[-1] # type: ignore
    
    def calculate_size_of_image(pe):        
        # Calculate the virtual address of the last section
        virtual_address = last_img_section.VirtualAddress + last_img_section.Misc_VirtualSize
        # Calculate the aligned size of image
        return (virtual_address + pe.OPTIONAL_HEADER.SectionAlignment - 1) & ~(pe.OPTIONAL_HEADER.SectionAlignment - 1)
    
    def calculate_size_of_code(pe):
        code_size = 0
        for section in pe.sections:
            if section.Characteristics & 0x20:  # IMAGE_SCN_CNT_CODE flag
                code_size =  code_size + section.SizeOfRawData
                
        return code_size
    
    size_of_image = calculate_size_of_image(pe)
    size_of_code = calculate_size_of_code(pe)
    
    def bugfix_calculation(value, default):
        if value == 0:
            return default
        return value
    
    size_of_image = bugfix_calculation(size_of_image, pe.OPTIONAL_HEADER.SizeOfImage - 0x5000)
    size_of_code = bugfix_calculation(size_of_code, pe.OPTIONAL_HEADER.SizeOfCode - 0x4200)

    pe.OPTIONAL_HEADER.SizeOfImage = size_of_image
    pe.OPTIONAL_HEADER.SizeOfCode = size_of_code
    
    # backup infected .exe
    directory, filename = os.path.split(exe_path)
    new_filename = os.path.splitext(filename)[0] + ".exe.virus"
    new_path = os.path.join(directory, new_filename)
    shutil.copy(exe_path, new_path)    

    # remove bytes beginning from the entry point of the virus
    new_exe_data = pe.write()[:entry_point_virus_file_offset]
    pe.close()
    
    # clear bytes of virus image section
    for i in range(virus_img_section_file_offset, virus_img_section_file_offset + 40):
        new_exe_data[i] = 0
    
    # overwrite exe
    with open(exe_path, 'wb') as file:
        file.write(new_exe_data)
    
    # to calculate checksum read file again, calculate and overwrite it
    pe = pefile.PE(exe_path)
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum() # type: ignore
    new_exe_data = pe.write()
    pe.close()
    with open(exe_path, 'wb') as file:
        file.write(new_exe_data) # type: ignore

def check_exe(exe_path): 
    try:
        pe = pefile.PE(exe_path)    
    except:
        return False
    
    last_section = pe.sections[-1]  
    if last_section.Characteristics != VIRUS_CHARACTERISTICS:
        pe.close()
        return False
    
    entry_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint) # type: ignore
    
    with open(exe_path, "+rb") as file:
        file.seek(entry_offset)
        entry_bytes = file.read(len(VIRUS_ENTRY_BYTES))
        
        if entry_bytes != VIRUS_ENTRY_BYTES:
            pe.close()
            return False
        
    # Virus detected
    remove_virus(pe, exe_path)
    
    return True

def add_to_context_menu():
    # Get the path to the current Python executable
    python_path = os.path.abspath(os.path.join(sys.prefix, "python.exe"))

    # Create the registry key for the context menu
    key_path = r"Software\Classes\*\shell\Scan File\command"
    reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)

    # Set the command to execute the Python script with the file path as argument
    winreg.SetValueEx(reg_key, "", 0, winreg.REG_SZ, f'"{python_path}" "{os.path.abspath(__file__)}" --file "%1"')
    print("To the context menu added.")

def remove_from_context_menu():
    def delete_sub_key(root, sub):
        try:
            open_key = winreg.OpenKey(root, sub, 0, winreg.KEY_ALL_ACCESS)
            num, _, _ = winreg.QueryInfoKey(open_key)
            for i in range(num):
                child = winreg.EnumKey(open_key, 0)
                delete_sub_key(open_key, child)
            try:
                winreg.DeleteKey(open_key, "")
            except Exception:
                pass
            finally:
                winreg.CloseKey(open_key)
        except Exception:
            pass

    delete_sub_key(winreg.HKEY_CURRENT_USER, r"Software\Classes\*\shell\Scan File")
    print("From the context menu removed.")
    
def check_file(file):
    print(f"Checking file: {file}")
    try:
        virus = check_exe(file)
        
        if virus == True:
            print("!!!!!!!!!!!!!!!!!!")
            print("! VIRUS DETECTED !")
            print("!!!!!!!!!!!!!!!!!!")
            print()
            print("The virus has been removed from the file.")
            print("You might want to scan your whole PC with --scan 'C:\\\\' 'D:\\\\' (and all your other drives).")
            os.system("pause")
    except Exception as e:
        print(e)
        os.system("pause")

def scan_directory(directory):     
    print(f"Scanning directory: {directory}")
    
    n_virus = 0
    n_clean = 0
    n_error = 0
    
    def print_update():
        print(f'\rProgress: [{n_virus} with virus | {n_clean} without virus | {n_error} with errors | Total: {n_virus + n_clean + n_error}]', end='')
    
    for root, dirs, files in os.walk(directory):
        for filename in files:
            try:
                if os.path.splitext(filename)[1] == ".exe":
                    if check_exe(os.path.join(root, filename)):
                        n_virus = n_virus + 1
                    else:
                        n_clean = n_clean + 1
            except Exception as e:
                n_error = n_error + 1
                
            print_update()
    print()

@main_requires_admin
def main(): 
    parser = argparse.ArgumentParser(description="Anti-Unnamed-Virus-Tool")
    parser.add_argument('--file', help='Checks the specified file and removes the virus if found')
    parser.add_argument('--scan', nargs='+', help="Scans all .exe files in the specified directories. Multiple ones possible with --scan 'C:\\\\' 'D:\\\\' 'E:\\\\'")
    parser.add_argument('--add', action='store_true', help="Adds a 'Scan File' entry to the file explorer context menu")
    parser.add_argument('--remove', action='store_true', help="Removes the 'Scan File' entry from the context menu")

    args = parser.parse_args()
    
    if args.file:
        check_file(args.file)
    elif args.add:    
        add_to_context_menu()
    elif args.remove:    
        remove_from_context_menu()
    elif args.scan:
        for directory in args.scan:
            scan_directory(directory)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
