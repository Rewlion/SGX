#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define EI_NIDENT	16
#define MAX_PATH_LENGTH	1000

typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t Elf32_Sword;
typedef uint32_t Elf32_Word;

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;

/********* 32bit types *********/
typedef struct {
	unsigned char   e_ident[EI_NIDENT];
	Elf32_Half      e_type;
	Elf32_Half      e_machine;
	Elf32_Word      e_version;
	Elf32_Addr      e_entry;
	Elf32_Off       e_phoff;		//program header table’s file offset in bytes
	Elf32_Off       e_shoff;		//section header table’s file offset in bytes.
	Elf32_Word      e_flags;
	Elf32_Half      e_ehsize;		//ELF header’s size in bytes
	Elf32_Half      e_phentsize;	//Program Header ENTry SIZE
	Elf32_Half      e_phnum;		//number of entries in the program header table
	Elf32_Half      e_shentsize;	//ection header’s size in bytes
	Elf32_Half      e_shnum;		//number of entries in the section header table
	Elf32_Half      e_shstrndx;
} Elf32_Ehdr;

typedef struct {
	Elf32_Word      sh_name;
	Elf32_Word      sh_type;
	Elf32_Word      sh_flags;
	Elf32_Addr      sh_addr;
	Elf32_Off       sh_offset;
	Elf32_Word      sh_size;
	Elf32_Word      sh_link;
	Elf32_Word      sh_info;
	Elf32_Word      sh_addralign;
	Elf32_Word      sh_entsize;
} Elf32_Shdr;



/********* 64bit types *********/
typedef struct {
	unsigned char e_ident[EI_NIDENT];	/*  ELF  identification  */
	Elf64_Half e_type;			/*  Object  file  type  */
	Elf64_Half e_machine; 		/*  Machine  type  */
	Elf64_Word e_version;		/*  Object  file  version  */
	Elf64_Addr e_entry;			/*  Entry  point  address  */
	Elf64_Off e_phoff;			/*  Program  header  offset  */
	Elf64_Off e_shoff;			/*  Section  header  offset  */
	Elf64_Word e_flags;			/*  Processor-specific  flags  */
	Elf64_Half e_ehsize;		/*  ELF  header  size  */
	Elf64_Half e_phentsize;		/*  Size  of  program  header  entry  */
	Elf64_Half e_phnum;			/*  Number  of  program  header  entries  */
	Elf64_Half e_shentsize;		/*  Size  of  section  header  entry  */
	Elf64_Half e_shnum;			/*  Number  of  section  header  entries  */
	Elf64_Half e_shstrndx;		/*  Section  name  string  table  index  */
}  Elf64_Ehdr;

typedef struct {
	Elf64_Word sh_name;			/*  Section  name  */
	Elf64_Word sh_type;			/*  Section  type  */
	Elf64_Xword sh_flags;		/*  Section  attributes  */
	Elf64_Addr sh_addr;			/*  Virtual  address  in  memory  */
	Elf64_Off sh_offset;		/*  Offset  in  file  */
	Elf64_Xword sh_size;		/*  Size  of  section  */
	Elf64_Word sh_link;			/*  Link  to  other  section  */
	Elf64_Word sh_info;			/*  Miscellaneous  information  */
	Elf64_Xword sh_addralign;	/*  Address  alignment  boundary  */
	Elf64_Xword sh_entsize;		/*  Size  of  entries,  if  section  has  table  */
}  Elf64_Shdr;

typedef  struct
{
	Elf64_Word st_name;			/*  Symbol  name  */
	unsigned char st_info;		/*  Type  and  Binding  attributes  */
	unsigned char st_other;		/*  Reserved  */
	Elf64_Half st_shndx;		/*  Section  table  index  */
	Elf64_Addr st_value;		/*  Symbol  value  */
	Elf64_Xword st_size;		/*  Size  of  object  (e.g.,  common)  */
}  Elf64_Sym;

/****** Data type to enclave ******/
typedef struct {
	uint32_t func_offset;
	uint32_t func_size;
	unsigned char status;
}	Func_data;

Func_data mini_elf_parser(const char *elf_ptr, const char *func_name);
