/* ###
 * IP: Public Domain
 */
#ifndef _GDIS_H_
#define _GDIS_H_

#define BYTE_BUFFER_SIZE 128

#define LITTLE_ELF_FILE "little.elf" // built for intel x64
#define BIG_ELF_FILE "big.elf"

#define BUFF_SIZE 128

#define MAX_DIS_STRING 		128
#define MAX_BYTES_STRING 	64
#define MAX_BYTES			64
#define MAX_NUM_ENTRIES		64
#define MAX_ELF_FILE_PATH_LEN 512


typedef struct _DIS_INFO_{
    char disassemblyString[MAX_DIS_STRING];
    char bytesBufferAscii[MAX_BYTES_STRING];
    unsigned char bytesBufferBin[MAX_BYTES];

    int count; /* Number of bytes consumed */

    char insn_info_valid;		/* Branch info has been set. */
    char branch_delay_insns;	/* How many sequential insn's will run before
				   a branch takes effect.  (0 = normal) */
    char data_size;		/* Size of data reference in insn, in bytes */
    enum dis_insn_type insn_type;	/* Type of instruction */
    bfd_vma target;		/* Target address of branch or dref, if known;
				   zero if unknown.  */
    bfd_vma target2;		/* Second target address for dref2 */

} DIS_INFO, *PDIS_INFO;

static DIS_INFO disassemblyInfoBuffer[MAX_NUM_ENTRIES];

char mnemonic[32] = {0}, src[32] = {0}, dest[32] = {0}, arg[32] = {0};
char disassembled_buffer[BUFF_SIZE];


/* Pseudo FILE object for strings.  */
typedef struct
{
  // char *buffer;
  char buffer[BUFF_SIZE];
  size_t pos;
  size_t alloc;
} SFILE;


static SFILE sfile;

static char *default_target = NULL;	/* Default at runtime.  */

// ------------------------------------------------------------------------

void listSupportedArchMachTargets(void);

int objdump_sprintf (SFILE *f, const char *format, ...);

void configureDisassembleInfo(bfd* abfd,
							  disassemble_info* info, 
							  enum bfd_architecture arch, 
							  unsigned long mach, 
							  enum bfd_endian end);
							  
disassembler_ftype configureBfd(bfd* abfd, 
								enum bfd_architecture arch, 
								unsigned long mach, 
								enum bfd_endian endian, 
								disassemble_info* DI,
								disassembler_ftype* disassemble_fn);

int disassemble_buffer( disassembler_ftype disassemble_fn,
						disassemble_info *info,
						int* offset,						
						PDIS_INFO pDisInfo);

void processBuffer(unsigned char* buff, 
		   int buff_len,
		   bfd_vma buff_vma,
		   disassembler_ftype disassemble_fn, 
		   struct disassemble_info* DI);

				   
						



#endif
