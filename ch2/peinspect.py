import pefile
import argparse
from capstone import *
from colorama import Fore, Style

class FileInspector:

    def __init__(self, args):
        self.pe = pefile.PE(args["file"])

    def memory_map(self):

        print("Section\t\t   Virtual Address\t VirtualSize\t Raw Data")
        for section in self.pe.sections:
            print(f'''{Fore.YELLOW}{section.Name}\t{hex(section.VirtualAddress)}\t\t{hex(section.Misc_VirtualSize)}\t\t{section.SizeOfRawData}{Style.RESET_ALL}''')


    def d_entry_import(self):

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            print(f"{Fore.BLUE}{entry.dll}{Style.RESET_ALL}")
            for function in entry.imports:
                print(f"{Fore.GREEN}\t{function.name}{Style.RESET_ALL}")

    def disassembler_(self):
        
        entrypoint = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entrypoint_address = entrypoint + self.pe.OPTIONAL_HEADER.ImageBase
        binary_code = self.pe.get_memory_mapped_image()[entrypoint:entrypoint+100]
        disas = Cs(CS_ARCH_X86, CS_MODE_32)
        for instruction in disas.disasm(binary_code, entrypoint_address):
            print(f"{instruction.mnemonic}\t{instruction.op_str}")
        

def getparser():
    parser = argparse.ArgumentParser(description = "PE file parser")
    parser.add_argument("-f", "--file", required=True, type=str, help = "PE file location")
    parser.add_argument("-i", "--imports", required=False, type=str, help = "PE file imports table")
    parser.add_argument("-m", "--map", required=False, type=str, help = "PE file section mapping" )
    parser.add_argument("-d", "--disasm", required=False, type=str, help = "PE file disassembler" )
    args = vars(parser.parse_args())
    return args



def main():
    args = getparser()
    agent = FileInspector(args)

    if args["imports"] != None:
        agent.d_entry_import()
    if args["map"] != None:
        agent.memory_map()
    if args["disasm"] != None:
        agent.disassembler_()

if __name__ == "__main__":
    main()
