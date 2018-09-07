#include "parser.h"

/****** PARSER ITSELF! *******/
Func_data mini_elf_parser(const char *elf_ptr, const char *func_name) {
	Func_data func_data;
	func_data.func_offset = 0;
	func_data.func_size = 0;
	func_data.status = 255;
	
	//parsing ELF header.
	Elf64_Ehdr *elf64_Ehdr = (Elf64_Ehdr*)elf_ptr;
	Elf64_Off e_shoff = elf64_Ehdr->e_shoff;
	Elf64_Half e_shentsize = elf64_Ehdr->e_shentsize;		
	Elf64_Half e_shnum = elf64_Ehdr->e_shnum;
	Elf64_Half e_shstrndx = elf64_Ehdr->e_shstrndx;
	
	//Section header table found
	Elf64_Shdr *elf64_Shdr = (Elf64_Shdr*)(elf_ptr + e_shoff);
	//String table header in Sec.h.t. found
	Elf64_Shdr *shstr = (Elf64_Shdr*)((char*)elf64_Shdr + e_shentsize*e_shstrndx);
	Elf64_Addr str_addr = (Elf64_Addr)elf_ptr + shstr->sh_offset;
		
	//Searching for Symbol table and String Table
	Elf64_Half i;
	Elf64_Shdr *shsym = NULL;
	Elf64_Shdr *strtab = NULL;
	char Valid = 0;
	char *section_name;
	for(i = 0; i < e_shnum; i++) {
		section_name = (char*)(str_addr + elf64_Shdr->sh_name);
		if(strcmp(section_name,".symtab") == 0) {
			shsym = elf64_Shdr;
			Valid ++;
		}
		if(strcmp(section_name,".strtab") == 0) {
			strtab = elf64_Shdr;
			Valid ++;
		}
		if (Valid == 2) break;
		
		elf64_Shdr = (Elf64_Shdr*)((char*)elf64_Shdr + e_shentsize);
	}
	
	if (Valid != 2) {
		func_data.status = 0;
		if(shsym == NULL) func_data.status += 1;
		if(strtab == NULL) func_data.status += 2;
		return func_data;
	}
	
	//Searching for function
	Elf64_Addr sym_addr = (Elf64_Addr)elf_ptr + shsym->sh_offset;
	Elf64_Addr strtab_addr = (Elf64_Addr)elf_ptr + strtab->sh_offset;
	Elf64_Xword sym_size = shsym->sh_size;
	Elf64_Xword sym_entsize = shsym->sh_entsize;
	Elf64_Xword sym_entoff;	
	Elf64_Sym *elf64_Sym;
	char *sym_name;
	for(sym_entoff = 0; sym_entoff < sym_size; sym_entoff += sym_entsize) {
		elf64_Sym = (Elf64_Sym*)(sym_addr+sym_entoff);
		sym_name = (char*)(strtab_addr + elf64_Sym->st_name);
		if(strcmp(sym_name, func_name) == 0) {
			/* WARNING! 0x00400000 = WORKAROND!!*/
			func_data.func_offset = elf64_Sym->st_value - 0x00400000;
			func_data.func_size = elf64_Sym->st_size;
			func_data.status = 0;
		}
	}
	if(sym_entoff >= sym_size && func_data.status != 0)
		func_data.status = 64;
	
	return func_data;
}
