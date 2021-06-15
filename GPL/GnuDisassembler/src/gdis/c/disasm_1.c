/* ###
 * IP: Public Domain
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "bfd.h"
#include "dis-asm.h"
// #include "bucomm.h" // for set_default_bfd_target()

#include "gdis.h"

#define MAX_ASCII_CHAR_BYTE_STRING 256


void listSupportedArchMachTargets(void)
{
	const char** targetList;
	const char** archList;
	int i, j;

	targetList = bfd_target_list();
	if(targetList != NULL){
		for(i=0, j=0; targetList[i] !=0; i++){
			printf("Supported Target: %s\n", targetList[i]);			
		}
	}
	printf("\ndone with targetList.\n");

	archList = bfd_arch_list();
	if(archList != NULL){
		for(i=0, j=0; archList[i] !=0; i++){
			printf("Supported Arch: %s\n", archList[i]);			
		}
	}
	printf("\ndone with archList.\n");
}



/* sprintf to a "stream".  */
int objdump_sprintf (SFILE *f, const char *format, ...)
{

	int i;
	size_t n;
	va_list args;

	va_start (args, format);
	n = vsnprintf (f->buffer + f->pos, BUFF_SIZE, format, args);
	strncat(disassembled_buffer, f->buffer, n);
	va_end (args);

	return n;
}


void configureDisassembleInfo(bfd* abfd,
		disassemble_info* info,
		enum bfd_architecture arch,
		unsigned long mach,
		enum bfd_endian end)
{

	memset(sfile.buffer, 0x00, BUFF_SIZE);

	INIT_DISASSEMBLE_INFO(*info, stdout, objdump_sprintf);
	info->arch = (enum bfd_architecture) arch;
	info->mach = mach;
	info->flavour = bfd_get_flavour(abfd);	
	info->endian = end;
	info->stream = (FILE*)&sfile; // set up our "buffer stream"
	info->display_endian = BFD_ENDIAN_LITTLE;
	/* Allow the target to customize the info structure.  */
	disassemble_init_for_target(info);
}

disassembler_ftype configureBfd(bfd* abfd, 
		enum bfd_architecture arch,
		unsigned long mach,
		enum bfd_endian endian,
		disassemble_info* DI,
		disassembler_ftype* disassemble_fn)
{	
	struct bfd_target *xvec;

	abfd->flags |= EXEC_P;


	// set up xvec byteorder. 
	xvec = (struct bfd_target *) malloc (sizeof (struct bfd_target));
	memset(xvec, 0x00, sizeof (struct bfd_target));	
	memcpy (xvec, abfd->xvec, sizeof (struct bfd_target));
	xvec->byteorder = endian;
	abfd->xvec = xvec;

	configureDisassembleInfo(abfd, DI, arch, mach, endian);
	if(endian == BFD_ENDIAN_BIG){
		bfd_big_endian(abfd);
		DI->display_endian = DI->endian = BFD_ENDIAN_BIG;
	}
	else{
		bfd_little_endian(abfd);
		DI->display_endian = DI->endian = BFD_ENDIAN_LITTLE;
	}

	/*
	bfd_error_type err = bfd_get_error();
	printf("bfd_error_msg: %s.\n", bfd_errmsg(err));
	 */

	/* Use libopcodes to locate a suitable disassembler.  */
	*disassemble_fn = NULL;
	*disassemble_fn = disassembler (arch, endian == BFD_ENDIAN_BIG, mach, abfd);
	if (!*disassemble_fn){
		printf("can't disassemble for arch 0x%08X, mach 0x%08lX\n", arch, mach);
		exit(1);
	}

	return *disassemble_fn;
}



int disassemble_buffer( disassembler_ftype disassemble_fn,
		disassemble_info *info,
		int* offset,
		PDIS_INFO pDisInfo)
{
	int i, j, size = 0;
	int len = 0;

	while ( *offset < info->buffer_length ) {
		/* call the libopcodes disassembler */
		memset(pDisInfo->disassemblyString, 0x00, MAX_DIS_STRING);

		/* set the insn_info_valid bit to 0, as explained in BFD's
		 * include/dis-asm.h. The bit will then be set to tell us
		 * whether the decoder supports "extra" information about the
		 * instruction.
		 */
		info->insn_info_valid = 0;

		size = (*disassemble_fn)(info->buffer_vma + *offset, info);
		/* -- analyze disassembled instruction here -- */
		/* -- print any symbol names as labels here -- */

		/* save off corresponding hex bytes */
		for ( j= 0,i = 0; i < 8; i++, j+=3) {
			if ( i < size ){				
				sprintf(&(pDisInfo->bytesBufferAscii[j]), "%02X ", info->buffer[*offset + i]);
				pDisInfo->bytesBufferBin[i] = info->buffer[*offset + i];
			}
		}

		/* add the augmented information to our disassembly info struct */
		pDisInfo->count = size;
		pDisInfo->insn_info_valid = info->insn_info_valid;
		pDisInfo->branch_delay_insns = info->branch_delay_insns;
		pDisInfo->data_size = info->data_size;
		pDisInfo->insn_type = info->insn_type;
		pDisInfo->target = info->target;
		pDisInfo->target2 = info->target2;

		strcat(&(pDisInfo->disassemblyString[0]), disassembled_buffer);
		memset(disassembled_buffer, 0x00, BUFF_SIZE);

		if(size != 0){
			*offset += size; /* advance position in buffer */
			goto END;
		}
	}

	END:
	return size;
}

void processBuffer(unsigned char* buff, 
		int buff_len,
		bfd_vma buff_vma,
		disassembler_ftype disassemble_fn,
		struct disassemble_info* DI)
{
	int bytesConsumed = -1;
	int offset = 0;
	int numDisassemblies = 0;
	int i;

	DI->buffer = buff; /* buffer of bytes to disassemble */
	DI->buffer_length = buff_len; /* size of buffer */
	DI->buffer_vma = buff_vma; /* base RVA of buffer */

	memset(disassemblyInfoBuffer, 0x00, sizeof(DIS_INFO)*MAX_NUM_ENTRIES);

	while((buff_len - offset) > 0 && bytesConsumed != 0 && numDisassemblies < MAX_NUM_ENTRIES){
		bytesConsumed = disassemble_buffer( disassemble_fn, DI, &offset, &(disassemblyInfoBuffer[numDisassemblies++]));	
	}
	for (i = 0; i < numDisassemblies; i++) {
		printf("%s\nInfo: %d,%d,%d,%d,%d\n", disassemblyInfoBuffer[i].disassemblyString,
				disassemblyInfoBuffer[i].count,
				disassemblyInfoBuffer[i].insn_info_valid,
				disassemblyInfoBuffer[i].branch_delay_insns,
				disassemblyInfoBuffer[i].data_size,
				disassemblyInfoBuffer[i].insn_type);
	}
}

int main(int argc, char* argv[]){
	struct disassemble_info DI;
	enum bfd_architecture arch;
	struct bfd_arch_info ai;
	unsigned long mach;
	enum bfd_endian endian;
	unsigned int end;
	bfd_vma offset;
	disassembler_ftype disassemble_fn;
	char *target = default_target;
	bfd *bfdfile;
	unsigned long a,m;
	char* byteString;
	char elf_file_location[MAX_ELF_FILE_PATH_LEN];
	char arch_str[256];
	char mach_str[256];

	if ( argc < 8) {
		fprintf(stderr, "Usage: %s target-str, arch, mach, disassembly base-addr (for rel offsets instrs), full-path to Little and Big Elfs, big/little ascii-byte-string up to %d chars\n", argv[0], MAX_ASCII_CHAR_BYTE_STRING);
		listSupportedArchMachTargets();
		const char** archList = bfd_arch_list();
		const bfd_arch_info_type* ait;
		while(*archList != NULL){
			printf("checking against architecture: %s.\n", *archList);
			ait = NULL;
			ait = bfd_scan_arch(*archList);
			if(ait != NULL){
				printf("archname: %s arch: 0x%08X, mach: 0x%08lX.\n", ait->arch_name, ait->arch, ait->mach);
			}
			archList++;
		}
		return(1);
	}

	end = 0x00000000;
	endian = (enum bfd_endian) 0x00;
	mach = 0x00000000;
	arch = (enum bfd_architecture) 0x00;
	offset = 0x00000000;

	sscanf(argv[2], "%128s", arch_str);
	sscanf(argv[3], "%18lX", &mach);
	sscanf(argv[4], "%10X", &end);
	sscanf(argv[5], "%18lX", &offset);

	// if arch starts with 0x, then parse a number
	//  else lookup the string in the table to get the arch, ignore the mach
	if (arch_str[0] == '0' && arch_str[1] == 'x') {
		sscanf(arch_str, "%10X", &arch);
	} else {
		const char** archList = bfd_arch_list();
		const bfd_arch_info_type* ait;
		while(*archList != NULL){
			ait = bfd_scan_arch(*archList);
			if(strcmp(arch_str, *archList)== 0){
				arch = ait->arch;
				mach = ait->mach;
				break;
			}
			ait = NULL;
			archList++;
		}
		if (ait == NULL) {
			printf("Couldn't find arch %s\n", arch_str);
			return(-1);
		}
	}


	endian = (enum bfd_endian) end;
	/* open a correct type of file to fill in most of the required data. */

	//	printf("Arch is: 0x%08X, Machine is: 0x%08lX Endian is: 0x%02X.\n", arch, mach, endian);

	memset(elf_file_location, 0x00, MAX_ELF_FILE_PATH_LEN);
	strncpy(elf_file_location, argv[6], MAX_ELF_FILE_PATH_LEN-sizeof(LITTLE_ELF_FILE)-2); // actual file name and nulls

	// arg[7] is either a hex string or the string "stdin", which
	// triggers reading line by line from stdin.

	byteString  = argv[7];
	int stdin_mode = 2; // use CLI
	if (strcmp(byteString, "stdin") == 0) {
		stdin_mode = 1; // use STDIN
	}

	if (endian == BFD_ENDIAN_BIG){
		strcat(elf_file_location, BIG_ELF_FILE);
	}
	else {
		strcat(elf_file_location, LITTLE_ELF_FILE);
	}

	bfd_init();

	while (stdin_mode) {

		//bfd_init();
		// convert user input AsciiHex to Binary data for processing
		char tmp[3];
		unsigned int byteValue;
		tmp[0] = tmp[1]  = tmp[2] = 0x00;
		char disassemblerOptions[128] = {0};
		unsigned char byteBuffer[BYTE_BUFFER_SIZE] = {0};
		char byteStringBuffer[(BYTE_BUFFER_SIZE*2)] = {0};
		char addressStringBuffer[128] = {0};
		char bytesAndOptionsBuffer[BYTE_BUFFER_SIZE*2 + sizeof(disassemblerOptions)] = {0};

		if (stdin_mode == 1) { // use stdin
			// read in the address
			if (fgets(addressStringBuffer, sizeof(addressStringBuffer), stdin)) {
				sscanf(addressStringBuffer, "%18lX", &offset);
			}
			//Read in the rest of the input. There are two possible styles:
			//"old": input is just the bytes to disassemble
		    //"new": input = bytes"*"<disassmbler_options>
			//for compatibility reasons, handle both styles
			if (fgets(bytesAndOptionsBuffer, sizeof(bytesAndOptionsBuffer), stdin)) {
				char *p = strchr(bytesAndOptionsBuffer, '*');
				if (p) {
					strncpy(byteStringBuffer,bytesAndOptionsBuffer,(int) (p - bytesAndOptionsBuffer));
					strncpy(disassemblerOptions,p+1,sizeof(disassemblerOptions));
					p = strchr(disassemblerOptions,'\n');
					if (p){
						*p = '\0';
					}
				}
				else {
					//no "*" in the string, so no disassembly options
					//replace newline with null terminator
					strncpy(byteStringBuffer, bytesAndOptionsBuffer, sizeof(byteStringBuffer));
					p = strchr(byteStringBuffer,'\n');
					if (p){
						*p = '\0';
					}
				}
			}
			else {
				fprintf(stderr, "exiting, no ASCII hex found\n");
				return 0; // finished! #TODO
			}
		}
		else {
			if(strlen(byteString) > BYTE_BUFFER_SIZE*2) {
				fprintf(stderr, "Max ascii string size is %d you provided: %lu chars. Exiting.\n", BYTE_BUFFER_SIZE*2,
						strlen(byteString));
				exit(-1);
			}
			strncpy(byteStringBuffer, byteString, BYTE_BUFFER_SIZE*2);
			stdin_mode = 0; // break out of the while loop
		}

		int size = strlen(byteStringBuffer);
		if((size % 2) != 0){
			fprintf(stderr, "need even-number of ascii chars for byte-stream: (offset: %08lx, %s, %ld)\n", offset, byteStringBuffer, strlen(byteStringBuffer));
			exit(-1);
		}

		memset(byteBuffer, 0x00, BYTE_BUFFER_SIZE);

		//
		// TODO:
		// check to make sure chars are only valid HEX.
		//
		int i, j;
		for(i=j=0; (i < size) && (j < BYTE_BUFFER_SIZE); i+=2, j++){
			tmp[0] = byteStringBuffer[i];
			tmp[1] = byteStringBuffer[i+1];
			tmp[2] = 0;
			sscanf(tmp, "%02X", &byteValue);
			byteBuffer[j] = (unsigned char)byteValue;
		}

		/*
		  for(j=0; j < BYTE_BUFFER_SIZE; j++){
		  printf("0x%02X ", byteBuffer[j]);
		  }
		 */

		//bfd_init( );
		target = argv[1];
		bfd_set_default_target(target);

		//		printf("Debug: BFD sample file: %s\n", elf_file_location);
		//		printf("Debug: LITTLE: %s\n", LITTLE_ELF_FILE);
		//		printf("Debug: BIG: %s\n", BIG_ELF_FILE);

		if(endian == BFD_ENDIAN_BIG){
			bfdfile = bfd_openr(elf_file_location, target );
			if ( ! bfdfile ) {
				printf("Error opening BIG ELF file: %s\n", elf_file_location);
				bfd_perror( "Error on bfdfile" );
				return(3);
			}
		}
		else{
			bfdfile = bfd_openr(elf_file_location, target );
			if ( ! bfdfile ) {
				printf("Error opening LITTLE ELF file: %s\n", elf_file_location);
				// bfdfile = bfd_openr(elf_file_location, target );
				bfd_perror( "Error on bfdfile" );
				return(3);
			}
		}

		memset((void*) &DI, 0x00, sizeof(struct disassemble_info));

		disassemble_fn = NULL;

		// important set up!
		//---------------------------------------
		ai.arch = arch;
		ai.mach = mach;
		bfd_set_arch_info(bfdfile, &ai);
		//---------------------------------------

		/*
		  bfd_error_type err = bfd_get_error();
		  printf("bfd_error_msg: %s.\n", bfd_errmsg(err));
		 */

		/*if (disassemblerOptions[0] != '\0'){
		    DI.disassembler_options = disassemblerOptions;
		}*/
		configureBfd(bfdfile, arch, mach, endian, &DI, &disassemble_fn);

		/*
		  err = bfd_get_error();
		  printf("bfd_error_msg: %s.\n", bfd_errmsg(err));
		 */

		if (disassemble_fn == NULL){
			fprintf(stderr, "Error: disassemble_fn is NULL. Nothing I can do.\n");
			exit(1);
		}
		else{
			/*
			  printf("the disassemble_fn func pointer is: 0x%08X.\n", disassemble_fn);
			  printf("We can try to disassemble for this arch/mach. calling disassemble_init_for_target().\n");
			 */

			disassemble_init_for_target(&DI);
			if (disassemblerOptions[0] != '\0'){
				DI.disassembler_options = disassemblerOptions;
			}

			// go diassemble the buffer and build up the result in a accumulator string buffer.
			processBuffer(byteBuffer, size >> 1, offset, disassemble_fn, &DI); //

		}

		free((void*)bfdfile->xvec);
		bfd_close(bfdfile);

		printf("EOF\n");
		fflush(stdout);

	} // while loop on lines of stdin

	return 0;
}
