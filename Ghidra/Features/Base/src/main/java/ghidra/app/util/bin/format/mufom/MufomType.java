/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License; Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing; software
 * distributed under the License is distributed on an "AS IS" BASIS;
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND; either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.mufom;

public abstract class MufomType {

	/* 0x00 - 0x7f - regular string or one byte number */

	/* 0x80 - omitted optional number field */
	public static final int MUFOM_OMITTED = 0x80;

	/* 0x81 - 0x88 - numbers outside range of 0-127 */

	/* 0x89 - 0x8f - unused  */

	/* 0x90 - 0xa0 - user defined function codes */

	/* 0xdb - 0xdd - unused */

	/* 0xfa - 0xff - unused */

	/* Function @F */
	public static final int MUFOM_FUNC_F = 0xa0;

	/* Function @T */
	public static final int MUFOM_FUNC_T = 0xa1;

	/* Function @ABS */
	public static final int MUFOM_FUNC_ABS = 0xa2;

	/* Function @NEG */
	public static final int MUFOM_FUNC_NEG = 0xa3;

	/* Function @NOT */
	public static final int MUFOM_FUNC_NOT = 0xa4;

	/* Function + */
	public static final int MUFOM_FUNC_ADD = 0xa5;

	/* Function - */
	public static final int MUFOM_FUNC_SUB = 0xa6;

	/* Function / */
	public static final int MUFOM_FUNC_DIV = 0xa7;

	/* Function * */
	public static final int MUFOM_FUNC_MUL = 0xa8;

	/* Function @MAX */
	public static final int MUFOM_FUNC_MAX = 0xa9;

	/* Function @MIN */
	public static final int MUFOM_FUNC_MIN = 0xaa;

	/* Function @MOD */
	public static final int MUFOM_FUNC_MOD = 0xab;

	/* Function < */
	public static final int MUFOM_FUNC_LT = 0xac;

	/* Function > */
	public static final int MUFOM_FUNC_GT = 0xad;

	/* Function = */
	public static final int MUFOM_FUNC_EQ = 0xae;

	/* Function != */
	public static final int MUFOM_FUNC_NEQ = 0xaf;

	/* Function @AND */
	public static final int MUFOM_FUNC_AND = 0xb0;

	/* Function @OR */
	public static final int MUFOM_FUNC_OR = 0xb1;

	/* Function @XOR */
	public static final int MUFOM_FUNC_XOR = 0xb2;

	/* Function @EXT */
	public static final int MUFOM_FUNC_EXT = 0xb3;

	/* Function @INS */
	public static final int MUFOM_FUNC_INS = 0xb4;

	/* Function @ERR */
	public static final int MUFOM_FUNC_ERR = 0xb5;

	/* Function @IF */
	public static final int MUFOM_FUNC_IF = 0xb6;

	/* Function @ELSE */
	public static final int MUFOM_FUNC_ELSE = 0xb7;

	/* Function @END */
	public static final int MUFOM_FUNC_END = 0xb8;

	/* Function @ISDEF */
	public static final int MUFOM_FUNC_ISDEF = 0xb9;

	/* Identifier NULL */
	public static final int MUFOM_ID_NULL = 0xc0;

	/* Identifier A */
	public static final int MUFOM_ID_A = 0xc1;

	/* Identifier B */
	public static final int MUFOM_ID_B = 0xc2;

	/* Identifier C */
	public static final int MUFOM_ID_C = 0xc3;

	/* Identifier D */
	public static final int MUFOM_ID_D = 0xc4;

	/* Identifier E */
	public static final int MUFOM_ID_E = 0xc5;

	/* Identifier F */
	public static final int MUFOM_ID_F = 0xc6;

	/*
	 * Identifier G
	 * Execution starting address
	 */
	public static final int MUFOM_ID_G = 0xc7;

	/* Identifier H */
	public static final int MUFOM_ID_H = 0xc8;

	/*
	 * Identifier I
	 * Address of public symbol
	 */
	public static final int MUFOM_ID_I = 0xc9;

	/* Identifier J */
	public static final int MUFOM_ID_J = 0xca;

	/* Identifier K */
	public static final int MUFOM_ID_K = 0xcb;

	/* Identifier L */
	public static final int MUFOM_ID_L = 0xcc;

	/* Identifier M */
	public static final int MUFOM_ID_M = 0xcd;

	/*
	 * Identifier N
	 * Address of local symbol
	 */
	public static final int MUFOM_ID_N = 0xce;

	/*
	 * Attribute Definition - Static symbol
	 * [x1] and [x2] - record and address
	 */
	public static final int MUFOM_AD_STATICSYMBOL = 0x13;

	/*
	 * Attribute Definition - Object format version number
	 * [x1] and [x2] defining version number and revision
	 */
	public static final int MUFOM_AD_VERSION = 0x25;

	/*
	 * Attribute Definition - Object format type
	 * [x1] defining type, 1 Absolute
	 */
	public static final int MUFOM_AD_TYPE = 0x26;

	/*
	 * Attribute Definition - Case sensitivity
	 * [x1] defining sensitivity, 2 Do not change the case of symbols
	 */
	public static final int MUFOM_AD_CASE = 0x27;

	/*
	 * Attribute Definition - Creation date and time
	 * [x1], [x2], [x3], [x4], [x5], [x6], year/month/day/hour/minute/second
	 * No ASN
	 */
	public static final int MUFOM_AD_DATETIME = 0x32;

	/*
	 * Attribute Definition - Command line text
	 * [id] command line
	 * No ASN
	 */
	public static final int MUFOM_AD_COMMANDLINE = 0x33;

	/*
	 * Attribute Definition - Execution status
	 * [x1] 0 Success
	 * No ASN
	 */
	public static final int MUFOM_AD_STATUS = 0x34;

	/*
	 * Attribute Definition - Host environment
	 * [x1]
	 * No ASN
	 */
	public static final int MUFOM_AD_ENV = 0x35;

	/*
	 * Attribute Definition - Tool and version number
	 * [x1], [x2], and [x3] (optional [x4] revision level) tool, version, revision
	 * No ASN
	 */
	public static final int MUFOM_AD_TOOLVERSION = 0x36;

	/*
	 * Attribute Definition - Comments
	 * [id] comments
	 * No ASN
	 */
	public static final int MUFOM_AT_COMMENT = 0x37;

	/* Identifier O */
	public static final int MUFOM_ID_O = 0xcf;

	/*
	 * Identifier P
	 * The program counter for section
	 * Implicitly changes with each LR, LD, or LT
	 */
	public static final int MUFOM_ID_P = 0xd0;

	/* Identifier Q */
	public static final int MUFOM_ID_Q = 0xd1;

	/* Identifier R */
	public static final int MUFOM_ID_R = 0xd2;

	/*
	 * Identifier S
	 * The size in minimum address units
	 */
	public static final int MUFOM_ID_S = 0xd3;

	/* Identifier T */
	public static final int MUFOM_ID_T = 0xd4;

	/* Identifier U */
	public static final int MUFOM_ID_U = 0xd5;

	/* Identifier V */
	public static final int MUFOM_ID_V = 0xd6;

	/*
	 * Identifier W
	 * The file offset in bytes of the part of the object file from the
	 * beginning of the file
	 */
	public static final int MUFOM_ID_W = 0xd7;

	/* Assign Value to Variable W0 (ASW0) - AD Extension Part*/
	public static final int MUFOM_ASW0 = 0x00;

	/* Assign Value to Variable W1 (ASW1) - Environment Part */
	public static final int MUFOM_ASW1 = 0x01;

	/* Assign Value to Variable W2 (ASW2) - Section Definition Part */
	public static final int MUFOM_ASW2 = 0x02;

	/* Assign Value to Variable W3 (ASW3) - External Part */
	public static final int MUFOM_ASW3 = 0x03;

	/* Assign Value to Variable W4 (ASW4) - Debug Information Definition Part */
	public static final int MUFOM_ASW4 = 0x04;

	/* Assign Value to Variable W5 (ASW5) - Data Part */
	public static final int MUFOM_ASW5 = 0x05;

	/* Assign Value to Variable W6 (ASW6) - Trailer Part */
	public static final int MUFOM_ASW6 = 0x06;

	/* Assign Value to Variable W7 (ASW7) */
	public static final int MUFOM_ASW7 = 0x07;

	/* Identifier X */
	public static final int MUFOM_ID_X = 0xd8;

	/* Identifier Y */
	public static final int MUFOM_ID_Y = 0xd9;

	/* Identifier Z */
	public static final int MUFOM_ID_Z = 0xda;

	/* Extension length 1-byte */
	public static final int MUFOM_EXTB = 0xde;

	/* Extension length 2-byte */
	public static final int MUFOM_EXTH = 0xdf;

	/* Command MB - Module begin */
	public static final int MUFOM_CMD_MB = 0xe0;

	/* Command ME - Module end */
	public static final int MUFOM_CMD_ME = 0xe1;

	/* Command AS - Assign */
	public static final int MUFOM_CMD_AS = 0xe2;

	/* Command IR - Initialize relocation base */
	public static final int MUFOM_CMD_IR = 0xe3;

	/* Command LR - Load with relocation */
	public static final int MUFOM_CMD_LR = 0xe4;

	/* Command SB - Section begin */
	public static final int MUFOM_CMD_SB = 0xe5;

	/* Command ST - Section type */
	public static final int MUFOM_CMD_ST = 0xe6;

	/* Command SA - Section alignment */
	public static final int MUFOM_CMD_SA = 0xe7;

	/* Command NI - Internal name */
	public static final int MUFOM_CMD_NI = 0xe8;

	/* Command NX - External name */
	public static final int MUFOM_CMD_NX = 0xe9;

	/* Command CO - Comment */
	public static final int MUFOM_CMD_CO = 0xea;

	/* Command DT - Date and time */
	public static final int MUFOM_CMD_DT = 0xeb;

	/* Command AD - Address description */
	public static final int MUFOM_CMD_AD = 0xec;

	/* Command LD - Load */
	public static final int MUFOM_CMD_LD = 0xed;

	/* Command CS (with sum) - Checksum followed by sum value */
	public static final int MUFOM_CMD_CSS = 0xee;

	/* Command CS - Checksum (reset sum to 0) */
	public static final int MUFOM_CMD_CS = 0xef;

	/* Command NN - Name */
	public static final int MUFOM_CMD_NN = 0xf0;

	/* Built-in Types ?, unknown type, 'UNKNOWN TYPE' */
	public static final int MUFOM_BUILTIN_UNK = 0x00;

	/* Built-in Types void, procedure returning void, 'void' */
	public static final int MUFOM_BUILTIN_V = 0x01;

	/* Built-in Types byte, 8-bit signed, 'signed char' */
	public static final int MUFOM_BUILTIN_B = 0x02;

	/* Built-in Types char, 8-bit unsigned, 'unsigned char' */
	public static final int MUFOM_BUILTIN_C = 0x03;

	/* Built-in Types halfword, 16-bit signed, 'signed short int' */
	public static final int MUFOM_BUILTIN_H = 0x04;

	/* Built-in Types int, 16-bit unsigned, 'unsigned short int' */
	public static final int MUFOM_BUILTIN_I = 0x05;

	/* Built-in Types long, 32-bit signed, 'signed long' */
	public static final int MUFOM_BUILTIN_L = 0x06;

	/* Built-in Types , 32-bit unsigned, 'unsigned long' */
	public static final int MUFOM_BUILTIN_M = 0x07;

	/* Built-in Types float, 32-bit floating point, 'float' */
	public static final int MUFOM_BUILTIN_F = 0x0a;

	/* Built-in Types double, 64-bit floating point, 'double' */
	public static final int MUFOM_BUILTIN_D = 0x0b;

	/* Built-in Types king size, extended precision floating point, 'long double' */
	public static final int MUFOM_BUILTIN_K = 0x0c;

	/* Built-in Types jump to, code location, 'instruction address' */
	public static final int MUFOM_BUILTIN_J = 0x0f;

	/* Built-in Pointer Types ?, unknown type, 'UNKNOWN TYPE' */
	public static final int MUFOM_BUILTIN_PUNK = 0x20;

	/* Built-in Pointer Types void, procedure returning void, 'void' */
	public static final int MUFOM_BUILTIN_PV = 0x21;

	/* Built-in Pointer Types byte, 8-bit signed, 'signed char' */
	public static final int MUFOM_BUILTIN_PB = 0x22;

	/* Built-in Pointer Types char, 8-bit unsigned, 'unsigned char' */
	public static final int MUFOM_BUILTIN_PC = 0x23;

	/* Built-in Pointer Types halfword, 16-bit signed, 'signed short int' */
	public static final int MUFOM_BUILTIN_PH = 0x24;

	/* Built-in Pointer Types int, 16-bit unsigned, 'unsigned short int' */
	public static final int MUFOM_BUILTIN_PI = 0x25;

	/* Built-in Pointer Types long, 32-bit signed, 'signed long' */
	public static final int MUFOM_BUILTIN_PL = 0x26;

	/* Built-in Pointer Types , 32-bit unsigned, 'unsigned long' */
	public static final int MUFOM_BUILTIN_PM = 0x27;

	/* Built-in Pointer Types float, 32-bit floating point, 'float' */
	public static final int MUFOM_BUILTIN_PF = 0x2a;

	/* Built-in Pointer Types double, 64-bit floating point, 'double' */
	public static final int MUFOM_BUILTIN_PD = 0x2b;

	/* Built-in Pointer Types king size, extended precision floating point, 'long double' */
	public static final int MUFOM_BUILTIN_PK = 0x2c;

	/* Command AT - Attribute */
	public static final int MUFOM_CMD_AT = 0xf1;

	/* Command TY - Type */
	public static final int MUFOM_CMD_TY = 0xf2;

	/* Command RI - Retain internal symbol */
	public static final int MUFOM_CMD_RI = 0xf3;

	/* Command WX - Weak external */
	public static final int MUFOM_CMD_WX = 0xf4;

	/* Command LI - Library search list*/
	public static final int MUFOM_CMD_LI = 0xf5;

	/* Command LX - Library external */
	public static final int MUFOM_CMD_LX = 0xf6;

	/* Command RE - Replicate */
	public static final int MUFOM_CMD_RE = 0xf7;

	/* Command SC - Scope definition */
	public static final int MUFOM_CMD_SC = 0xf8;

	/* Command LN - Line number */
	public static final int MUFOM_CMD_LN = 0xf9;

	public static final int ieee_number_start_enum = 0x00;
	public static final int ieee_unknown_1_enum = 0x01;
	public static final int ieee_unknown_7_enum = 0x07;
	public static final int ieee_unknown_12_enum = 0x0c;
	public static final int ieee_unknown_16_enum = 0x10;

	public static final int ieee_execution_tool_version_enum = 0x36;
	public static final int ieee_unknown_56_enum = 0x38;
	public static final int ieee_number_repeat_start_enum = 0x80;
	public static final int ieee_number_repeat_1_enum = 0x81;
	public static final int ieee_number_repeat_2_enum = 0x82;
	public static final int ieee_number_repeat_3_enum = 0x83;
	public static final int ieee_number_repeat_4_enum = 0x84;
	public static final int ieee_number_repeat_end_enum = 0x88;

	public static final int ieee_function_signed_open_b_enum = 0xba;
	public static final int ieee_function_signed_close_b_enum = 0xbb;
	public static final int ieee_function_unsigned_open_b_enum = 0xbc;
	public static final int ieee_function_unsigned_close_b_enum = 0xbd;
	public static final int MUFOM_OPEN = 0xbe;
	public static final int MUFOM_CLOSE = 0xbf;


	public static final int ieee_record_seperator_enum = 0xdb;

	public static final int ieee_attribute_record_enum = 0xc9;

	public static final int MUFOM_BB1 = 0x01;
	public static final int MUFOM_BB2 = 0x02;
	public static final int MUFOM_BB3 = 0x03;
	public static final int MUFOM_BB4 = 0x04;
	public static final int MUFOM_BB5 = 0x05;
	public static final int MUFOM_BB6 = 0x06;
	public static final int MUFOM_BB10 = 0x0a;
	public static final int MUFOM_BB11 = 0x0b;

}
