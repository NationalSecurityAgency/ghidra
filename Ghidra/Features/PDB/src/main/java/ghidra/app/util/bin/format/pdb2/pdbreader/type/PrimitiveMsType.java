/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;

/**
 * A class for a specific PDB data type--In this case one of many possible primitive types,
 *  specified by the record number.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class PrimitiveMsType extends AbstractMsType {

	protected int recNum;
	protected String typeString;
	protected int typeSize;

	/**
	 * Constructor for PrimitiveMsType
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param recNum Specific record number (ID) of the primitive type.
	 */
	public PrimitiveMsType(AbstractPdb pdb, int recNum) {
		super(pdb, null);
		this.recNum = recNum;
		processType();
	}

	@Override
	public int getPdbId() {
		return -1; // No real PDB_ID
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		if (builder.length() != 0) {
			builder.insert(0, " ");
		}
		builder.insert(0, typeString);
	}

	/**
	 * Returns the name of this primitive type.
	 * @return Name type of the primitive type.
	 */
	@Override
	public String getName() {
		return typeString;
	}

	/**
	 * Returns the type name of this primitive type.
	 * @return Type name the primitive type.
	 */
	public String getTypeString() {
		return typeString;
	}

	/**
	 * Returns the record number (ID) that indicates the type of primitive type.
	 * @return Specific record number (ID) representing the type of primitive.
	 */
	public int getNumber() {
		return recNum;
	}

	/**
	 * Returns the number of bytes that this primitive takes in instantiation.
	 * @return Number of bytes this primitive takes.
	 */
	public int getTypeSize() {
		return typeSize;
	}

	/**
	 * Indicates whether the type is a T_NOTYPE.
	 * @return Indicates whether T_NOTYPE.
	 */
	public boolean isNoType() {
		return recNum == 0;
	}

	//==============================================================================================
	private void processType() {
		switch (recNum) {
			//=======================================
			// Special types
			//=======================================
			// No Type (uncharacterized type)
			case 0x0000:
				typeString = "T_NOTYPE";
				typeSize = 0;
				break;
			// Absolute symbol
			case 0x0001:
				typeString = "T_ABS";
				typeSize = 0;
				break;
			// Segment type
			case 0x0002:
				typeString = "T_SEGMENT";
				typeSize = 0;
				break;
			// Void type
			case 0x0003:
				typeString = "void";
				typeSize = 0;
				break;
			// Near pointer to void
			case 0x0103:
				typeString = "void near*";
				typeSize = 2;
				break;
			// Far pointer to void
			case 0x0203:
				typeString = "void far*";
				typeSize = 4;
				break;
			// Huge pointer to void
			case 0x0303:
				typeString = "void huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to void
			case 0x0403:
				typeString = "void *";
				typeSize = 4;
				break;
			// 16:32 pointer to void
			case 0x0503:
				typeString = "T_32PFVOID";
				typeSize = 4;
				break;
			// 64-bit pointer to void
			case 0x0603:
				typeString = "T_64PFVOID";
				typeSize = 8;
				break;
			// 128-bit near pointer to void (LLVM doc on 0x0700)
			case 0x0703:
				typeString = "T_128PFVOID";
				typeSize = 16;
				break;
			// BASIC 8 byte currency value
			case 0x0004:
				typeString = "T_CURRENCY";
				typeSize = 8;
				break;
			// Near BASIC string
			case 0x0005:
				typeString = "T_NBASICSTR";
				typeSize = 0;
				break;
			// Far BASIC string
			case 0x0006:
				typeString = "T_FBASICSTR";
				typeSize = 0;
				break;
			// Type not translated by cvpack
			case 0x0007:
				typeString = "T_NOTTRANS";
				typeSize = 0;
				break;
			// OLE/COM HRESULT
			case 0x0008:
				typeString = "T_HRESULT";
				typeSize = 4;
				break;
			// OLE/COM HRESULT __ptr32 *
			case 0x0408:
				typeString = "T_32PHRESULT";
				typeSize = 4;
				break;
			// OLE/COM HRESULT __ptr64 *
			case 0x0608:
				typeString = "T_64PHRESULT";
				typeSize = 8;
				break;
			// OLE/COM HRESULT __ptr128 *  (LLVM doc on 0x0700)
			case 0x0708:
				typeString = "T_128PHRESULT";
				typeSize = 16;
				break;
			// bit
			case 0x0060:
				typeString = "T_BIT";
				typeSize = 0;
				break;
			// Pascal CHAR
			case 0x0061:
				typeString = "T_PASCHAR";
				typeSize = 0;
				break;
			// 32-bit BOOL where true is 0xffffffff
			case 0x0062:
				typeString = "T_BOOL32FF";
				typeSize = 0;
				break;

			//=======================================
			// Signed Character types
			//=======================================
			// 8-bit signed
			case 0x0010:
				typeString = "signed char";
				typeSize = 1;
				break;
			// 16-bit pointer to an 8-bit signed
			case 0x0110:
				typeString = "signed char near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to an 8-bit signed
			case 0x0210:
				typeString = "char far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to an 8-bit signed
			case 0x0310:
				typeString = "char huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to an 8-bit signed
			case 0x0410:
				typeString = "char *";
				typeSize = 4;
				break;
			// 16:32 pointer to an 8-bit signed
			case 0x0510:
				typeString = "T_32PFCHAR";
				typeSize = 6;
				break;
			// 64-bit pointer to an 8-bit signed
			case 0x0610:
				typeString = "T_64PCHAR";
				typeSize = 8;
				break;
			// 128-bit near pointer to an 8-bit signed (LLVM doc on 0x0700)
			case 0x0710:
				typeString = "T_128PCHAR";
				typeSize = 16;
				break;

			//=======================================
			// Unsigned Character types
			//=======================================
			// 8-bit unsigned 
			case 0x0020:
				typeString = "unsigned char";
				typeSize = 1;
				break;
			// 16-bit pointer to an 8-bit unsigned
			case 0x0120:
				typeString = "unsigned char near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to an 8-bit unsigned
			case 0x0220:
				typeString = "unsigned char far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to an 8-bit unsigned
			case 0x0320:
				typeString = "unsigned char huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to an 8-bit unsigned
			case 0x0420:
				typeString = "unsigned char *";
				typeSize = 4;
				break;
			// 16:32 pointer to an 8-bit unsigned
			case 0x0520:
				typeString = "T_32PFUCHAR";
				typeSize = 6;
				break;
			// 64-bit pointer to an 8-bit unsigned
			case 0x0620:
				typeString = "T_64PUCHAR";
				typeSize = 8;
				break;
			// 128-bit near pointer to an 8-bit unsigned (LLVM doc on 0x0700)
			case 0x0720:
				typeString = "T_128PUCHAR";
				typeSize = 16;
				break;

			//=======================================
			// Real character types
			//=======================================
			// a real char
			case 0x0070:
				typeString = "char";
				typeSize = 1;
				break;
			// 16-bit pointer to a real char
			case 0x0170:
				typeString = "char near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to a real char
			case 0x0270:
				typeString = "char far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a real char
			case 0x0370:
				typeString = "char huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to a real char
			case 0x0470:
				typeString = "char *";
				typeSize = 4;
				break;
			// 16:32 pointer to a real char
			case 0x0570:
				typeString = "T_32PFRCHAR";
				typeSize = 6;
				break;
			// 64-bit pointer to a real char
			case 0x0670:
				typeString = "T_64PRCHAR";
				typeSize = 8;
				break;
			// 128-bit near pointer to a real char (LLVM doc on 0x0700)
			case 0x0770:
				typeString = "T_128PRCHAR";
				typeSize = 16;
				break;

			//=======================================
			// Really a wide character types
			//=======================================
			// wide char
			case 0x0071:
				typeString = "wchar_t";
				typeSize = 2;
				break;
			// 16-bit pointer to a wide char
			case 0x0171:
				typeString = "wchar_t near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to a wide char
			case 0x0271:
				typeString = "wchar_t far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a wide char
			case 0x0371:
				typeString = "wchar_t huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to a wide char
			case 0x0471:
				typeString = "wchar_t *";
				typeSize = 4;
				break;
			// 16:32 pointer to a wide char
			case 0x0571:
				typeString = "T_32PFWCHAR";
				typeSize = 6;
				break;
			// 64-bit pointer to a wide char
			case 0x0671:
				typeString = "T_64PWCHAR";
				typeSize = 8;
				break;
			// 128-bit near pointer to a wide char (LLVM doc on 0x0700)
			case 0x0771:
				typeString = "T_128PWCHAR";
				typeSize = 16;
				break;

			//=======================================
			// 16-bit char types
			//=======================================
			// 16-bit unicode char
			case 0x007a:
				typeString = "T_CHAR16";
				typeSize = 2;
				break;
			// 16-bit pointer to a 16-bit unicode char 
			case 0x017a:
				typeString = "T_PCHAR16";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 16-bit unicode char
			case 0x027a:
				typeString = "T_PFCHAR16";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 16-bit unicode char
			case 0x037a:
				typeString = "T_PHCHAR16";
				typeSize = 4;
				break;
			// 32-bit pointer to a 16-bit unicode char
			case 0x047a:
				typeString = "T_32PCHAR16";
				typeSize = 4;
				break;
			// 16:32 pointer to a 16-bit unicode char
			case 0x057a:
				typeString = "T_32PFCHAR16";
				typeSize = 6;
				break;
			// 64-bit pointer to a 16-bit unicode char
			case 0x067a:
				typeString = "T_64PCHAR16";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 16-bit unicode char (LLVM doc on 0x0700)
			case 0x077a:
				typeString = "T_128PCHAR16";
				typeSize = 16;
				break;

			//=======================================
			// 32-bit unicode char types
			//=======================================
			// 32-bit unicode char
			case 0x007b:
				typeString = "T_CHAR32";
				typeSize = 4;
				break;
			// 16-bit pointer to a 32-bit unicode char 
			case 0x017b:
				typeString = "T_PCHAR32";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 32-bit unicode char
			case 0x027b:
				typeString = "T_PFCHAR32";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 32-bit unicode char
			case 0x037b:
				typeString = "T_PHCHAR32";
				typeSize = 4;
				break;
			// 32-bit pointer to a 32-bit unicode char
			case 0x047b:
				typeString = "T_32PCHAR32";
				typeSize = 4;
				break;
			// 16:32 pointer to a 32-bit unicode char
			case 0x057b:
				typeString = "T_32PFCHAR32";
				typeSize = 6;
				break;
			// 64-bit pointer to a 32-bit unicode char
			case 0x067b:
				typeString = "T_64PCHAR32";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 32-bit unicode char (LLVM doc on 0x0700)
			case 0x077b:
				typeString = "T_128PCHAR32";
				typeSize = 16;
				break;

			//=======================================
			// 8-bit int types
			//=======================================
			// 8-bit int
			case 0x0068:
				typeString = "T_INT1";
				typeSize = 1;
				break;
			// 16-bit pointer to an 8-bit int
			case 0x0168:
				typeString = "T_PINT1";
				typeSize = 2;
				break;
			// 16:16 far pointer to an 8-bit int
			case 0x0268:
				typeString = "T_PFINT1";
				typeSize = 4;
				break;
			// 16:16 huge pointer to an 8-bit int
			case 0x0368:
				typeString = "T_PHINT1";
				typeSize = 4;
				break;
			// 32-bit pointer to an 8-bit int
			case 0x0468:
				typeString = "T_32PINT1";
				typeSize = 4;
				break;
			// 16:32 pointer to an 8-bit int
			case 0x0568:
				typeString = "T_32PFINT1";
				typeSize = 6;
				break;
			// 64-bit pointer to an 8-bit int
			case 0x0668:
				typeString = "T_64PINT1";
				typeSize = 8;
				break;
			// 128-bit near pointer to an 8-bit int (LLVM doc on 0x0700)
			case 0x0768:
				typeString = "T_128PINT1";
				typeSize = 16;
				break;

			//=======================================
			// 8-bit unsigned int types
			//=======================================
			// 8-bit unsigned int
			case 0x0069:
				typeString = "T_UINT1";
				typeSize = 1;
				break;
			// 16-bit pointer to an 8-bit unsigned int
			case 0x0169:
				typeString = "T_PUINT1";
				typeSize = 2;
				break;
			// 16:16 far pointer to an 8-bit unsigned int
			case 0x0269:
				typeString = "T_PFUINT1";
				typeSize = 4;
				break;
			// 16:16 huge pointer to an 8-bit unsigned int
			case 0x0369:
				typeString = "T_PHUINT1";
				typeSize = 4;
				break;
			// 32-bit pointer to an 8-bit unsigned int
			case 0x0469:
				typeString = "T_32PUINT1";
				typeSize = 4;
				break;
			// 16:32 pointer to an 8-bit unsigned int
			case 0x0569:
				typeString = "T_32PFUINT1";
				typeSize = 6;
				break;
			// 64-bit pointer to an 8-bit unsigned int
			case 0x0669:
				typeString = "T_64PUINT1";
				typeSize = 8;
				break;
			// 128-bit near pointer to an 8-bit unsigned int (LLVM doc on 0x0700)
			case 0x0769:
				typeString = "T_128PUINT1";
				typeSize = 16;
				break;

			//=======================================
			// 16-bit short types
			//=======================================
			// 16-bit signed short
			case 0x0011:
				typeString = "short";
				typeSize = 2;
				break;
			// 16-bit pointer to a 16-bit signed short
			case 0x0111:
				typeString = "short near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 16-bit signed short
			case 0x0211:
				typeString = "short far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 16-bit signed short
			case 0x0311:
				typeString = "short huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to a 16-bit signed short
			case 0x0411:
				typeString = "T_32PSHORT";
				typeSize = 4;
				break;
			// 16:32 pointer to a 16-bit signed short
			case 0x0511:
				typeString = "T_32PFSHORT";
				typeSize = 6;
				break;
			// 64-bit pointer to a 16-bit signed short
			case 0x0611:
				typeString = "T_64PSHORT";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 16-bit signed short (LLVM doc on 0x0700)
			case 0x0711:
				typeString = "T_128PSHORT";
				typeSize = 16;
				break;

			//=======================================
			// 16-bit unsigned short types
			//=======================================
			// 16-bit unsigned signed short
			case 0x0021:
				typeString = "unsigned short";
				typeSize = 2;
				break;
			// 16-bit pointer to a 16-bit unsigned signed short
			case 0x0121:
				typeString = "unsigned short near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 16-bit unsigned signed short
			case 0x0221:
				typeString = "unsigned short far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 16-bit unsigned signed short
			case 0x0321:
				typeString = "unsigned short huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to a 16-bit unsigned signed short
			case 0x0421:
				typeString = "T_32PUSHORT";
				typeSize = 4;
				break;
			// 16:32 pointer to a 16-bit unsigned signed short
			case 0x0521:
				typeString = "T_32PFUSHORT";
				typeSize = 6;
				break;
			// 64-bit pointer to a 16-bit unsigned signed short
			case 0x0621:
				typeString = "T_64PUSHORT";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 16-bit unsigned signed short (LLVM doc on 0x0700)
			case 0x0721:
				typeString = "T_128PUSHORT";
				typeSize = 16;
				break;

			//=======================================
			// 16-bit signed int types
			//=======================================
			// 16-bit signed int
			case 0x0072:
				typeString = "int16";
				typeSize = 2;
				break;
			// 16-bit pointer to a 16-bit signed int
			case 0x0172:
				typeString = "int16 near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 16-bit signed int
			case 0x0272:
				typeString = "int16 far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 16-bit signed int
			case 0x0372:
				typeString = "int16 huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to a 16-bit signed int
			case 0x0472:
				typeString = "T_32PINT2";
				typeSize = 4;
				break;
			// 16:32 pointer to a 16-bit signed int
			case 0x0572:
				typeString = "T_32PFINT2";
				typeSize = 6;
				break;
			// 64-bit pointer to a 16-bit signed int
			case 0x0672:
				typeString = "T_64PINT2";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 16-bit signed int (LLVM doc on 0x0700)
			case 0x0772:
				typeString = "T_128PINT2";
				typeSize = 16;
				break;

			//=======================================
			// 16-bit unsigned int types
			//=======================================
			// 16-bit unsigned int
			case 0x0073:
				typeString = "unsigned int16";
				typeSize = 2;
				break;
			// 16-bit pointer to a 16-bit unsigned int
			case 0x0173:
				typeString = "unsigned int16 near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 16-bit unsigned int
			case 0x0273:
				typeString = "unsigned int16 far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 16-bit unsigned int
			case 0x0373:
				typeString = "unsigned int16 huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to a 16-bit unsigned int
			case 0x0473:
				typeString = "T_32PUINT2";
				typeSize = 4;
				break;
			// 16:32 pointer to a 16-bit unsigned int
			case 0x0573:
				typeString = "T_32PFUINT2";
				typeSize = 6;
				break;
			// 64-bit pointer to a 16-bit unsigned int
			case 0x0673:
				typeString = "T_64PUINT2";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 16-bit unsigned int (LLVM doc on 0x0700)
			case 0x0773:
				typeString = "T_128PUINT2";
				typeSize = 16;
				break;

			//=======================================
			// 32-bit long types
			//=======================================
			// 32-bit signed long
			case 0x0012:
				typeString = "long";
				typeSize = 4;
				break;
			// 16-bit pointer to a 32-bit signed long
			case 0x0112:
				typeString = "long near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 32-bit signed long
			case 0x0212:
				typeString = "long far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 32-bit signed long
			case 0x0312:
				typeString = "long huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to a 32-bit signed long
			case 0x0412:
				typeString = "T_32PLONG";
				typeSize = 4;
				break;
			// 16:32 pointer to a 32-bit signed long
			case 0x0512:
				typeString = "T_32PFLONG";
				typeSize = 6;
				break;
			// 64-bit pointer to a 32-bit signed long
			case 0x0612:
				typeString = "T_64PLONG";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 32-bit signed long (LLVM doc on 0x0700)
			case 0x0712:
				typeString = "T_128PLONG";
				typeSize = 16;
				break;

			//=======================================
			// 32-bit unsigned long types
			//=======================================
			// 32-bit unsigned signed long
			case 0x0022:
				typeString = "unsigned long";
				typeSize = 4;
				break;
			// 16-bit pointer to a 32-bit unsigned signed long
			case 0x0122:
				typeString = "unsigned long near*";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 32-bit unsigned signed long
			case 0x0222:
				typeString = "unsigned long far*";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 32-bit unsigned signed long
			case 0x0322:
				typeString = "unsigned long huge*";
				typeSize = 4;
				break;
			// 32-bit pointer to a 32-bit unsigned signed long
			case 0x0422:
				typeString = "T_32PULONG";
				typeSize = 4;
				break;
			// 16:32 pointer to a 32-bit unsigned signed long
			case 0x0522:
				typeString = "T_32PFULONG";
				typeSize = 6;
				break;
			// 64-bit pointer to a 32-bit unsigned signed long
			case 0x0622:
				typeString = "T_64PULONG";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 32-bit unsigned signed long (LLVM doc on 0x0700)
			case 0x0722:
				typeString = "T_128PULONG";
				typeSize = 16;
				break;

			//=======================================
			// 32-bit signed int types
			//=======================================
			// 32-bit signed int
			case 0x0074:
				typeString = "int";
				typeSize = 4;
				break;
			// 16-bit pointer to a 32-bit signed int
			case 0x0174:
				typeString = "PINT4";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 32-bit signed int
			case 0x0274:
				typeString = "PFINT4";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 32-bit signed int
			case 0x0374:
				typeString = "PHINT4";
				typeSize = 4;
				break;
			// 32-bit pointer to a 32-bit signed int
			case 0x0474:
				typeString = "T_32PINT4";
				typeSize = 4;
				break;
			// 16:32 pointer to a 32-bit signed int
			case 0x0574:
				typeString = "T_32PFINT4";
				typeSize = 6;
				break;
			// 64-bit pointer to a 32-bit signed int
			case 0x0674:
				typeString = "T_64PINT4";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 32-bit signed int (LLVM doc on 0x0700)
			case 0x0774:
				typeString = "T_128PINT4";
				typeSize = 16;
				break;

			//=======================================
			// 32-bit unsigned int types
			//=======================================
			// 32-bit unsigned int
			case 0x0075:
				typeString = "unsigned";
				typeSize = 4;
				break;
			// 16-bit pointer to a 32-bit unsigned int
			case 0x0175:
				typeString = "PUINT4";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 32-bit unsigned int
			case 0x0275:
				typeString = "PFUINT4";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 32-bit unsigned int
			case 0x0375:
				typeString = "PHUINT4";
				typeSize = 4;
				break;
			// 32-bit pointer to a 32-bit unsigned int
			case 0x0475:
				typeString = "T_32PUINT4";
				typeSize = 4;
				break;
			// 16:32 pointer to a 32-bit unsigned int
			case 0x0575:
				typeString = "T_32PFUINT4";
				typeSize = 6;
				break;
			// 64-bit pointer to a 32-bit unsigned int
			case 0x0675:
				typeString = "T_64PUINT4";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 32-bit unsigned int (LLVM doc on 0x0700)
			case 0x0775:
				typeString = "T_128PUINT4";
				typeSize = 16;
				break;

			//=======================================
			// 64-bit quad types
			//=======================================
			// 64-bit signed long
			case 0x0013:
				typeString = "T_QUAD";
				typeSize = 8;
				break;
			// 16-bit pointer to a 64-bit signed long
			case 0x0113:
				typeString = "T_PQUAD";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 64-bit signed long
			case 0x0213:
				typeString = "T_PFQUAD";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 64-bit signed long
			case 0x0313:
				typeString = "T_PHQUAD";
				typeSize = 4;
				break;
			// 32-bit pointer to a 64-bit signed long
			case 0x0413:
				typeString = "T_32PQUAD";
				typeSize = 4;
				break;
			// 16:32 pointer to a 64-bit signed long
			case 0x0513:
				typeString = "T_32PFQUAD";
				typeSize = 6;
				break;
			// 64-bit pointer to a 64-bit signed long
			case 0x0613:
				typeString = "T_64PQUAD";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 64-bit signed long (LLVM doc on 0x0700)
			case 0x0713:
				typeString = "T_128PQUAD";
				typeSize = 16;
				break;

			//=======================================
			// 64-bit unsigned quad types
			//=======================================
			// 64-bit unsigned signed long
			case 0x0023:
				typeString = "T_UQUAD";
				typeSize = 8;
				break;
			// 16-bit pointer to a 64-bit unsigned signed long
			case 0x0123:
				typeString = "T_PUQUAD";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 64-bit unsigned signed long
			case 0x0223:
				typeString = "T_PFUQUAD";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 64-bit unsigned signed long
			case 0x0323:
				typeString = "T_PHUQUAD";
				typeSize = 4;
				break;
			// 32-bit pointer to a 64-bit unsigned signed long
			case 0x0423:
				typeString = "T_32PUQUAD";
				typeSize = 4;
				break;
			// 16:32 pointer to a 64-bit unsigned signed long
			case 0x0523:
				typeString = "T_32PFUQUAD";
				typeSize = 6;
				break;
			// 64-bit pointer to a 64-bit unsigned signed long
			case 0x0623:
				typeString = "T_64PUQUAD";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 64-bit unsigned signed long (LLVM doc on 0x0700)
			case 0x0723:
				typeString = "T_128PUQUAD";
				typeSize = 16;
				break;

			//=======================================
			// 64-bit signed int types
			//=======================================
			// 64-bit signed int
			case 0x0076:
				typeString = "T_INT8";
				typeSize = 8;
				break;
			// 16-bit pointer to a 64-bit signed int
			case 0x0176:
				typeString = "T_PINT8";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 64-bit signed int
			case 0x0276:
				typeString = "T_PFINT8";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 64-bit signed int
			case 0x0376:
				typeString = "T_PHINT8";
				typeSize = 4;
				break;
			// 32-bit pointer to a 64-bit signed int
			case 0x0476:
				typeString = "T_32PINT8";
				typeSize = 4;
				break;
			// 16:32 pointer to a 64-bit signed int
			case 0x0576:
				typeString = "T_32PFINT8";
				typeSize = 6;
				break;
			// 64-bit pointer to a 64-bit signed int
			case 0x0676:
				typeString = "T_64PINT8";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 64-bit signed int (LLVM doc on 0x0700)
			case 0x0776:
				typeString = "T_128PINT8";
				typeSize = 16;
				break;

			//=======================================
			// 64-bit unsigned int types
			//=======================================
			// 64-bit unsigned int
			case 0x0077:
				typeString = "T_UINT8";
				typeSize = 8;
				break;
			// 16-bit pointer to a 64-bit unsigned int
			case 0x0177:
				typeString = "T_PUINT8";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 64-bit unsigned int
			case 0x0277:
				typeString = "T_PFUINT8";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 64-bit unsigned int
			case 0x0377:
				typeString = "T_PHUINT8";
				typeSize = 4;
				break;
			// 32-bit pointer to a 64-bit unsigned int
			case 0x0477:
				typeString = "T_32PUINT8";
				typeSize = 4;
				break;
			// 16:32 pointer to a 64-bit unsigned int
			case 0x0577:
				typeString = "T_32PFUINT8";
				typeSize = 6;
				break;
			// 64-bit pointer to a 64-bit unsigned int
			case 0x0677:
				typeString = "T_64PUINT8";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 64-bit unsigned int (LLVM doc on 0x0700)
			case 0x0777:
				typeString = "T_128PUINT8";
				typeSize = 16;
				break;

			//=======================================
			// 128-bit octet types
			//=======================================
			// 128-bit signed long
			case 0x0014:
				typeString = "T_OCT";
				typeSize = 16;
				break;
			// 16-bit pointer to a 128-bit signed long
			case 0x0114:
				typeString = "T_POCT";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 128-bit signed long
			case 0x0214:
				typeString = "T_PFOCT";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 128-bit signed long
			case 0x0314:
				typeString = "T_PHOCT";
				typeSize = 4;
				break;
			// 32-bit pointer to a 128-bit signed long
			case 0x0414:
				typeString = "T_32POCT";
				typeSize = 4;
				break;
			// 16:32 pointer to a 128-bit signed long
			case 0x0514:
				typeString = "T_32PFOCT";
				typeSize = 6;
				break;
			// 64-bit pointer to a 128-bit signed long
			case 0x0614:
				typeString = "T_64POCT";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 128-bit signed long (LLVM doc on 0x0700)
			case 0x0714:
				typeString = "T_128POCT";
				typeSize = 16;
				break;

			//=======================================
			// 128-bit unsigned octet types
			//=======================================
			// 128-bit unsigned signed long
			case 0x0024:
				typeString = "T_UOCT";
				typeSize = 16;
				break;
			// 16-bit pointer to a 128-bit unsigned signed long
			case 0x0124:
				typeString = "T_PUOCT";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 128-bit unsigned signed long
			case 0x0224:
				typeString = "T_PFUOCT";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 128-bit unsigned signed long
			case 0x0324:
				typeString = "T_PHUOCT";
				typeSize = 4;
				break;
			// 32-bit pointer to a 128-bit unsigned signed long
			case 0x0424:
				typeString = "T_32PUOCT";
				typeSize = 4;
				break;
			// 16:32 pointer to a 128-bit unsigned signed long
			case 0x0524:
				typeString = "T_32PFUOCT";
				typeSize = 6;
				break;
			// 64-bit pointer to a 128-bit unsigned signed long
			case 0x0624:
				typeString = "T_64PUOCT";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 128-bit unsigned signed long (LLVM doc on 0x0700)
			case 0x0724:
				typeString = "T_128PUOCT";
				typeSize = 16;
				break;

			//=======================================
			// 128-bit signed int types
			//=======================================
			// 128-bit signed int
			case 0x0078:
				typeString = "T_INT16";
				typeSize = 16;
				break;
			// 16-bit pointer to a 128-bit signed int
			case 0x0178:
				typeString = "T_PINT16";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 128-bit signed int
			case 0x0278:
				typeString = "T_PFINT16";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 128-bit signed int
			case 0x0378:
				typeString = "T_PHINT16";
				typeSize = 4;
				break;
			// 32-bit pointer to a 128-bit signed int
			case 0x0478:
				typeString = "T_32PINT16";
				typeSize = 4;
				break;
			// 16:32 pointer to a 128-bit signed int
			case 0x0578:
				typeString = "T_32PFINT16";
				typeSize = 6;
				break;
			// 64-bit pointer to a 128-bit signed int
			case 0x0678:
				typeString = "T_64PINT16";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 128-bit signed int (LLVM doc on 0x0700)
			case 0x0778:
				typeString = "T_128PINT16";
				typeSize = 16;
				break;

			//=======================================
			// 128-bit unsigned int types
			//=======================================
			// 128-bit unsigned int
			case 0x0079:
				typeString = "T_UINT16";
				typeSize = 16;
				break;
			// 16-bit pointer to a 128-bit unsigned int
			case 0x0179:
				typeString = "T_PUINT16";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 128-bit unsigned int
			case 0x0279:
				typeString = "T_PFUINT16";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 128-bit unsigned int
			case 0x0379:
				typeString = "T_PHUINT16";
				typeSize = 4;
				break;
			// 32-bit pointer to a 128-bit unsigned int
			case 0x0479:
				typeString = "T_32PUINT16";
				typeSize = 4;
				break;
			// 16:32 pointer to a 128-bit unsigned int
			case 0x0579:
				typeString = "T_32PFUINT16";
				typeSize = 6;
				break;
			// 64-bit pointer to a 128-bit unsigned int
			case 0x0679:
				typeString = "T_64PUINT16";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 128-bit unsigned int (LLVM doc on 0x0700)
			case 0x0779:
				typeString = "T_128PUINT16";
				typeSize = 16;
				break;

			//=======================================
			// 16-bit real types
			//=======================================
			// 16-bit real
			case 0x0046:
				typeString = "T_REAL16";
				typeSize = 2;
				break;
			// 16-bit pointer to a 16-bit real
			case 0x0146:
				typeString = "T_PREAL16";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 16-bit real
			case 0x0246:
				typeString = "T_PFREAL16";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 16-bit real
			case 0x0346:
				typeString = "T_PHREAL16";
				typeSize = 4;
				break;
			// 32-bit pointer to a 16-bit real
			case 0x0446:
				typeString = "T_32PREAL16";
				typeSize = 4;
				break;
			// 16:32 pointer to a 16-bit real
			case 0x0546:
				typeString = "T_32PFREAL16";
				typeSize = 6;
				break;
			// 64-bit pointer to a 16-bit real
			case 0x0646:
				typeString = "T_64PREAL16";
				typeSize = 8;
				break;
			// 128-bit pointer to a 16-bit real (LLVM doc on 0x0700)
			case 0x0746:
				typeString = "T_128PREAL16";
				typeSize = 16;
				break;

			//=======================================
			// 32-bit real types
			//=======================================
			// 32-bit real
			case 0x0040:
				typeString = "T_REAL32";
				typeSize = 4;
				break;
			// 16-bit pointer to a 32-bit real
			case 0x0140:
				typeString = "T_PREAL32";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 32-bit real
			case 0x0240:
				typeString = "T_PFREAL32";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 32-bit real
			case 0x0340:
				typeString = "T_PHREAL32";
				typeSize = 4;
				break;
			// 32-bit pointer to a 32-bit real
			case 0x0440:
				typeString = "T_32PREAL32";
				typeSize = 4;
				break;
			// 16:32 pointer to a 32-bit real
			case 0x0540:
				typeString = "T_32PFREAL32";
				typeSize = 6;
				break;
			// 64-bit pointer to a 32-bit real
			case 0x0640:
				typeString = "T_64PREAL32";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 32-bit real (LLVM doc on 0x0700)
			case 0x0740:
				typeString = "T_128PREAL32";
				typeSize = 16;
				break;

			//=======================================
			// 32-bit partial-precision real types
			//=======================================
			// 32-bit real
			case 0x0045:
				typeString = "T_REAL32PP";
				typeSize = 4;
				break;
			// 16-bit pointer to a 32-bit real
			case 0x0145:
				typeString = "T_PREAL32PP";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 32-bit real
			case 0x0245:
				typeString = "T_PFREAL32PP";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 32-bit real
			case 0x0345:
				typeString = "T_PHREAL32PP";
				typeSize = 4;
				break;
			// 32-bit pointer to a 32-bit real
			case 0x0445:
				typeString = "T_32PREAL32PP";
				typeSize = 4;
				break;
			// 16:32 pointer to a 32-bit real
			case 0x0545:
				typeString = "T_32PFREAL32PP";
				typeSize = 6;
				break;
			// 64-bit pointer to a 32-bit real
			case 0x0645:
				typeString = "T_64PREAL32PP";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 32-bit real (LLVM doc on 0x0700)
			case 0x0745:
				typeString = "T_128PREAL32PP";
				typeSize = 16;
				break;

			//=======================================
			// 48-bit real types
			//=======================================
			// 48-bit real
			case 0x0044:
				typeString = "T_REAL48";
				typeSize = 6;
				break;
			// 16-bit pointer to a 48-bit real
			case 0x0144:
				typeString = "T_PREAL48";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 48-bit real
			case 0x0244:
				typeString = "T_PFREAL48";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 48-bit real
			case 0x0344:
				typeString = "T_PHREAL48";
				typeSize = 4;
				break;
			// 32-bit pointer to a 48-bit real
			case 0x0444:
				typeString = "T_32PREAL48";
				typeSize = 4;
				break;
			// 16:32 pointer to a 48-bit real
			case 0x0544:
				typeString = "T_32PFREAL48";
				typeSize = 6;
				break;
			// 64-bit pointer to a 48-bit real
			case 0x0644:
				typeString = "T_64PREAL48";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 48-bit real (LLVM doc on 0x0700)
			case 0x0744:
				typeString = "T_128PREAL48";
				typeSize = 16;
				break;

			//=======================================
			// 64-bit real types
			//=======================================
			// 64-bit real
			case 0x0041:
				typeString = "T_REAL64";
				typeSize = 8;
				break;
			// 16-bit pointer to a 64-bit real
			case 0x0141:
				typeString = "T_PREAL64";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 64-bit real
			case 0x0241:
				typeString = "T_PFREAL64";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 64-bit real
			case 0x0341:
				typeString = "T_PHREAL64";
				typeSize = 4;
				break;
			// 32-bit pointer to a 64-bit real
			case 0x0441:
				typeString = "T_32PREAL64";
				typeSize = 4;
				break;
			// 16:32 pointer to a 64-bit real
			case 0x0541:
				typeString = "T_32PFREAL64";
				typeSize = 6;
				break;
			// 64-bit pointer to a 64-bit real
			case 0x0641:
				typeString = "T_64PREAL64";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 64-bit real (LLVM doc on 0x0700)
			case 0x0741:
				typeString = "T_128PREAL64";
				typeSize = 16;
				break;

			//=======================================
			// 80-bit real types
			//=======================================
			// 80-bit real
			case 0x0042:
				typeString = "T_REAL80";
				typeSize = 10;
				break;
			// 16-bit pointer to an 80-bit real
			case 0x0142:
				typeString = "T_PREAL80";
				typeSize = 2;
				break;
			// 16:16 far pointer to an 80-bit real
			case 0x0242:
				typeString = "T_PFREAL80";
				typeSize = 4;
				break;
			// 16:16 huge pointer to an 80-bit real
			case 0x0342:
				typeString = "T_PHREAL80";
				typeSize = 4;
				break;
			// 32-bit pointer to an 80-bit real
			case 0x0442:
				typeString = "T_32PREAL80";
				typeSize = 4;
				break;
			// 16:32 pointer to an 80-bit real
			case 0x0542:
				typeString = "T_32PFREAL80";
				typeSize = 6;
				break;
			// 64-bit pointer to an 80-bit real
			case 0x0642:
				typeString = "T_64PREAL80";
				typeSize = 8;
				break;
			// 128-bit near pointer to an 80-bit real (LLVM doc on 0x0700)
			case 0x0742:
				typeString = "T_128PREAL80";
				typeSize = 16;
				break;

			//=======================================
			// 128-bit real types
			//=======================================
			// 128-bit real
			case 0x0043:
				typeString = "T_REAL128";
				typeSize = 16;
				break;
			// 16-bit pointer to a 128-bit real
			case 0x0143:
				typeString = "T_PREAL128";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 128-bit real
			case 0x0243:
				typeString = "T_PFREAL128";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 128-bit real
			case 0x0343:
				typeString = "T_PHREAL128";
				typeSize = 4;
				break;
			// 32-bit pointer to a 128-bit real
			case 0x0443:
				typeString = "T_32PREAL128";
				typeSize = 4;
				break;
			// 16:32 pointer to a 128-bit real
			case 0x0543:
				typeString = "T_32PFREAL128";
				typeSize = 6;
				break;
			// 64-bit pointer to a 128-bit real
			case 0x0643:
				typeString = "T_64PREAL128";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 128-bit real (LLVM doc on 0x0700)
			case 0x0743:
				typeString = "T_128PREAL128";
				typeSize = 16;
				break;

			//=======================================
			// 32-bit complex types
			//=======================================
			// 32-bit complex
			case 0x0050:
				typeString = "T_CPLX32";
				typeSize = 4;
				break;
			// 16-bit pointer to a 32-bit complex
			case 0x0150:
				typeString = "T_PCPLX32";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 32-bit complex
			case 0x0250:
				typeString = "T_PFCPLX32";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 32-bit complex
			case 0x0350:
				typeString = "T_PHCPLX32";
				typeSize = 4;
				break;
			// 32-bit pointer to an 32-bit complex
			case 0x0450:
				typeString = "T_32PCPLX32";
				typeSize = 4;
				break;
			// 16:32 pointer to an 32-bit complex
			case 0x0550:
				typeString = "T_32PFCPLX32";
				typeSize = 6;
				break;
			// 64-bit pointer to an 32-bit complex
			case 0x0650:
				typeString = "T_64PCPLX32";
				typeSize = 8;
				break;
			// 128-bit near pointer to an 32-bit complex (LLVM doc on 0x0700)
			case 0x0750:
				typeString = "T_128PCPLX32";
				typeSize = 16;
				break;

			//=======================================
			// 64-bit complex types
			//=======================================
			// 64-bit complex
			case 0x0051:
				typeString = "T_CPLX64";
				typeSize = 8;
				break;
			// 16-bit pointer to a 64-bit complex
			case 0x0151:
				typeString = "T_PCPLX64";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 64-bit complex
			case 0x0251:
				typeString = "T_PFCPLX64";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 64-bit complex
			case 0x0351:
				typeString = "T_PHCPLX64";
				typeSize = 4;
				break;
			// 32-bit pointer to a 64-bit complex
			case 0x0451:
				typeString = "T_32PCPLX64";
				typeSize = 4;
				break;
			// 16:32 pointer to a 64-bit complex
			case 0x0551:
				typeString = "T_32PFCPLX64";
				typeSize = 6;
				break;
			// 64-bit pointer to a 64-bit complex
			case 0x0651:
				typeString = "T_64PCPLX64";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 64-bit complex (LLVM doc on 0x0700)
			case 0x0751:
				typeString = "T_128PCPLX64";
				typeSize = 16;
				break;

			//=======================================
			// 80-bit complex types
			//=======================================
			// 80-bit complex
			case 0x0052:
				typeString = "T_CPLX80";
				typeSize = 10;
				break;
			// 16-bit pointer to an 80-bit complex
			case 0x0152:
				typeString = "T_PCPLX80";
				typeSize = 2;
				break;
			// 16:16 far pointer to an 80-bit complex
			case 0x0252:
				typeString = "T_PFCPLX80";
				typeSize = 4;
				break;
			// 16:16 huge pointer to an 80-bit complex
			case 0x0352:
				typeString = "T_PHCPLX80";
				typeSize = 4;
				break;
			// 32-bit pointer to an 80-bit complex
			case 0x0452:
				typeString = "T_32PCPLX80";
				typeSize = 4;
				break;
			// 16:32 pointer to an 80-bit complex
			case 0x0552:
				typeString = "T_32PFCPLX80";
				typeSize = 6;
				break;
			// 64-bit pointer to an 80-bit complex
			case 0x0652:
				typeString = "T_64PCPLX80";
				typeSize = 8;
				break;
			// 128-bit near pointer to an 80-bit complex (LLVM doc on 0x0700)
			case 0x0752:
				typeString = "T_128PCPLX80";
				typeSize = 16;
				break;

			//=======================================
			// 128-bit complex types
			//=======================================
			// 128-bit complex
			case 0x0053:
				typeString = "T_CPLX128";
				typeSize = 16;
				break;
			// 16-bit pointer to a 128-bit complex
			case 0x0153:
				typeString = "T_PCPLX128";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 128-bit complex
			case 0x0253:
				typeString = "T_PFCPLX128";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 128-bit complex
			case 0x0353:
				typeString = "T_PHCPLX128";
				typeSize = 4;
				break;
			// 32-bit pointer to a 128-bit complex
			case 0x0453:
				typeString = "T_32PCPLX128";
				typeSize = 4;
				break;
			// 16:32 pointer to a 128-bit complex
			case 0x0553:
				typeString = "T_32PFCPLX128";
				typeSize = 6;
				break;
			// 64-bit pointer to a 128-bit complex
			case 0x0653:
				typeString = "T_64PCPLX128";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 128-bit complex (LLVM doc on 0x0700)
			case 0x0753:
				typeString = "T_128PCPLX128";
				typeSize = 16;
				break;

			//=======================================
			// 8-bit boolean types
			//=======================================
			// 8-bit boolean
			case 0x0030:
				typeString = "T_BOOL08";
				typeSize = 1;
				break;
			// 16-bit pointer to an 8-bit boolean
			case 0x0130:
				typeString = "T_PBOOL08";
				typeSize = 2;
				break;
			// 16:16 far pointer to an 8-bit boolean
			case 0x0230:
				typeString = "T_PFBOOL08";
				typeSize = 4;
				break;
			// 16:16 huge pointer to an 8-bit boolean
			case 0x0330:
				typeString = "T_PHBOOL08";
				typeSize = 4;
				break;
			// 32-bit pointer to an 8-bit boolean
			case 0x0430:
				typeString = "T_32PBOOL08";
				typeSize = 4;
				break;
			// 16:32 pointer to an 8-bit boolean
			case 0x0530:
				typeString = "T_32PFBOOL08";
				typeSize = 6;
				break;
			// 64-bit pointer to an 8-bit boolean
			case 0x0630:
				typeString = "T_64PBOOL08";
				typeSize = 8;
				break;
			// 128-bit near pointer to an 8-bit boolean (LLVM doc on 0x0700)
			case 0x0730:
				typeString = "T_128PBOOL08";
				typeSize = 16;
				break;

			//=======================================
			// 16-bit boolean types
			//=======================================
			// 16-bit boolean
			case 0x0031:
				typeString = "T_BOOL16";
				typeSize = 2;
				break;
			// 16-bit pointer to a 16-bit boolean
			case 0x0131:
				typeString = "T_PBOOL16";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 16-bit boolean
			case 0x0231:
				typeString = "T_PFBOOL16";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 16-bit boolean
			case 0x0331:
				typeString = "T_PHBOOL16";
				typeSize = 4;
				break;
			// 32-bit pointer to a 16-bit boolean
			case 0x0431:
				typeString = "T_32PBOOL16";
				typeSize = 4;
				break;
			// 16:32 pointer to a 16-bit boolean
			case 0x0531:
				typeString = "T_32PFBOOL16";
				typeSize = 6;
				break;
			// 64-bit pointer to a 16-bit boolean
			case 0x0631:
				typeString = "T_64PBOOL16";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 16-bit boolean (LLVM doc on 0x0700)
			case 0x0731:
				typeString = "T_128PBOOL16";
				typeSize = 16;
				break;

			//=======================================
			// 32-bit boolean types
			//=======================================
			// 32-bit boolean
			case 0x0032:
				typeString = "T_BOOL32";
				typeSize = 4;
				break;
			// 16-bit pointer to a 32-bit boolean
			case 0x0132:
				typeString = "T_PBOOL32";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 32-bit boolean
			case 0x0232:
				typeString = "T_PFBOOL32";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 32-bit boolean
			case 0x0332:
				typeString = "T_PHBOOL32";
				typeSize = 4;
				break;
			// 32-bit pointer to a 32-bit boolean
			case 0x0432:
				typeString = "T_32PBOOL32";
				typeSize = 4;
				break;
			// 16:32 pointer to a 32-bit boolean
			case 0x0532:
				typeString = "T_32PFBOOL32";
				typeSize = 6;
				break;
			// 64-bit pointer to a 32-bit boolean
			case 0x0632:
				typeString = "T_64PBOOL32";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 32-bit boolean (LLVM doc on 0x0700)
			case 0x0732:
				typeString = "T_128PBOOL32";
				typeSize = 16;
				break;

			//=======================================
			// 64-bit boolean types
			//=======================================
			// 64-bit boolean
			case 0x0033:
				typeString = "T_BOOL64";
				typeSize = 8;
				break;
			// 16-bit pointer to a 64-bit boolean
			case 0x0133:
				typeString = "T_PBOOL64";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 64-bit boolean
			case 0x0233:
				typeString = "T_PFBOOL64";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 64-bit boolean
			case 0x0333:
				typeString = "T_PHBOOL64";
				typeSize = 4;
				break;
			// 32-bit pointer to a 64-bit boolean
			case 0x0433:
				typeString = "T_32PBOOL64";
				typeSize = 4;
				break;
			// 16:32 pointer to a 64-bit boolean
			case 0x0533:
				typeString = "T_32PFBOOL64";
				typeSize = 6;
				break;
			// 64-bit pointer to a 64-bit boolean
			case 0x0633:
				typeString = "T_64PBOOL64";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 64-bit boolean (LLVM doc on 0x0700)
			case 0x0733:
				typeString = "T_128PBOOL64";
				typeSize = 16;
				break;

			//=======================================
			// 128-bit boolean types
			//=======================================
			// 128-bit boolean
			case 0x0034:
				typeString = "T_BOOL128";
				typeSize = 16;
				break;
			// 16-bit pointer to a 128-bit boolean
			case 0x0134:
				typeString = "T_PBOOL128";
				typeSize = 2;
				break;
			// 16:16 far pointer to a 128-bit boolean
			case 0x0234:
				typeString = "T_PFBOOL128";
				typeSize = 4;
				break;
			// 16:16 huge pointer to a 128-bit boolean
			case 0x0334:
				typeString = "T_PHBOOL128";
				typeSize = 4;
				break;
			// 32-bit pointer to a 128-bit boolean
			case 0x0434:
				typeString = "T_32PBOOL128";
				typeSize = 4;
				break;
			// 16:32 pointer to a 128-bit boolean
			case 0x0534:
				typeString = "T_32PFBOOL128";
				typeSize = 6;
				break;
			// 64-bit pointer to a 128-bit boolean
			case 0x0634:
				typeString = "T_64PBOOL128";
				typeSize = 8;
				break;
			// 128-bit near pointer to a 128-bit boolean (LLVM doc on 0x0700)
			case 0x0734:
				typeString = "T_128PBOOL128";
				typeSize = 16;
				break;

			//=======================================
			// Internal type with pointers
			//=======================================
			// CV Internal type for created near pointers
			case 0x01f0:
				typeString = "T_NCVPTR";
				typeSize = 2;
				break;
			// CV Internal type for created far pointers
			case 0x02f0:
				typeString = "T_FCVPTR";
				typeSize = 4;
				break;
			// CV Internal type for created huge pointers
			case 0x03f0:
				typeString = "T_HCVPTR";
				typeSize = 4;
				break;
			// CV Internal type for created near 32-bit pointers
			case 0x04f0:
				typeString = "T_32NCVPTR";
				typeSize = 4;
				break;
			// CV Internal type for created far 32-bit pointers
			case 0x05f0:
				typeString = "T_32FCVPTR";
				typeSize = 6;
				break;
			// CV Internal type for created near 64-bit pointers
			case 0x06f0:
				typeString = "T_64NCVPTR";
				typeSize = 8;
				break;
			// CV Internal type for created near 128-bit near pointers (LLVM doc on 0x0700)
			case 0x07f0:
				typeString = "T_128NCVPTR";
				typeSize = 16;
				break;

			default:
				pdb.getPdbReaderMetrics().witnessPrimitive(recNum);
				typeString = String.format("_UnknownPrimitiveType0X%04X_", recNum);
				typeSize = 1; // unknown
				break;

		}
	}

}
