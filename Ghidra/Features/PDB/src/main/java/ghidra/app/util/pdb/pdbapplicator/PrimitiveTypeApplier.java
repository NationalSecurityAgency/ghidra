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
package ghidra.app.util.pdb.pdbapplicator;

import java.math.BigInteger;

import ghidra.app.util.bin.format.pdb2.pdbreader.type.PrimitiveMsType;
import ghidra.program.model.data.DataType;

/**
 * Applier for {@link PrimitiveMsType} types.
 */
public class PrimitiveTypeApplier extends MsTypeApplier {

	/**
	 * Constructor for primitive type applier, for transforming a primitive into a
	 * Ghidra DataType.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link PrimitiveMsType} to process.
	 */
	public PrimitiveTypeApplier(PdbApplicator applicator, PrimitiveMsType msType) {
		super(applicator, msType);
		apply(); // Only apply in constructor for primitives
	}

	@Override
	BigInteger getSize() {
		return BigInteger.valueOf(((PrimitiveMsType) msType).getTypeSize());
	}

	@Override
	void apply() {
		dataType = applyPrimitiveMsType((PrimitiveMsType) msType);
	}

	boolean isNoType() {
		return (((PrimitiveMsType) msType).getNumber() == 0);
	}

	private DataType applyPrimitiveMsType(PrimitiveMsType type) {
		DataType primitiveDataType = null;
//		String name = type.getName();
//
//		DataTypeManager applicatorDataTypeManager = applicator.getDataTypeManager();
//		DataTypeManager builtInDataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
//		DataType dataType =
//			builtInDataTypeManager.getDataType(new DataTypePath(CategoryPath.ROOT, name));
//		if (dataType != null) {
//			return dataType.clone(applicatorDataTypeManager);
//		}

		PdbPrimitiveTypeApplicator primitiveApplicator = applicator.getPdbPrimitiveTypeApplicator();

		switch (type.getNumber()) {
			//=======================================
			// Special types
			//=======================================
			// No Type (uncharacterized type)
			case 0x0000:
				primitiveDataType = primitiveApplicator.getNoType(type);
				break;
			// Absolute symbol
			case 0x0001:
				primitiveDataType = primitiveApplicator.getNoType(type);
				break;
			// Segment type
			case 0x0002:
				primitiveDataType = primitiveApplicator.getNoType(type);
				break;
			// Void type
			case 0x0003:
				primitiveDataType = primitiveApplicator.getVoidType();
				break;
			// Near pointer to void
			case 0x0103:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.getVoidType());
				break;
			// Far pointer to void
			case 0x0203:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.getVoidType());
				break;
			// Huge pointer to void
			case 0x0303:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.getVoidType());
				break;
			// 32-bit pointer to void
			case 0x0403:
				primitiveDataType =
					primitiveApplicator.get32PointerType(type, primitiveApplicator.getVoidType());
				break;
			// 16:32 pointer to void
			case 0x0503:
				primitiveDataType =
					primitiveApplicator.get1632PointerType(type, primitiveApplicator.getVoidType());
				break;
			// 64-bit pointer to void
			case 0x0603:
				primitiveDataType =
					primitiveApplicator.get64PointerType(type, primitiveApplicator.getVoidType());
				break;
			// 128-bit near pointer to void (LLVM doc on 0x0700)
			case 0x0703:
				primitiveDataType =
					primitiveApplicator.get128PointerType(type, primitiveApplicator.getVoidType());
				break;
			// BASIC 8 byte currency value
			case 0x0004:
				primitiveDataType = primitiveApplicator.createTypedefNamedSizedType(type);
				break;
			// Near BASIC string
			case 0x0005:
				primitiveDataType = primitiveApplicator.createUnmappedPdbType(type);
				break;
			// Far BASIC string
			case 0x0006:
				primitiveDataType = primitiveApplicator.createUnmappedPdbType(type);
				break;
			// Type not translated by cvpack
			case 0x0007:
				primitiveDataType = primitiveApplicator.createUnmappedPdbType(type);
				break;
			// OLE/COM HRESULT
			case 0x0008:
				primitiveDataType = primitiveApplicator.createTypedefNamedSizedType(type);
				break;
			// OLE/COM HRESULT __ptr32 *
			case 0x0408: // TODO: Make true pointer version
				primitiveDataType = primitiveApplicator.createTypedefNamedSizedType(type);
				break;
			// OLE/COM HRESULT __ptr64 *
			case 0x0608: // TODO: Make true pointer version
				primitiveDataType = primitiveApplicator.createTypedefNamedSizedType(type);
				break;
			// OLE/COM HRESULT __ptr128 *
			case 0x0708: // TODO: Make true pointer version
				primitiveDataType = primitiveApplicator.createTypedefNamedSizedType(type);
				break;
			// bit
			case 0x0060:
				primitiveDataType = primitiveApplicator.createUnmappedPdbType(type);
				break;
			// Pascal CHAR
			case 0x0061:
				primitiveDataType = primitiveApplicator.createUnmappedPdbType(type);
				break;
			// 32-bit BOOL where true is 0xffffffff
			case 0x0062:
				primitiveDataType =
					primitiveApplicator.createTypedefNamedSizedType("T_BOOL32FF", 4);
				break;

			//=======================================
			// Signed Character types
			//=======================================
			// 8-bit signed
			case 0x0010:
				primitiveDataType = primitiveApplicator.getSignedCharType();
				break;
			// 16-bit pointer to an 8-bit signed
			case 0x0110:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.getSignedCharType());
				break;
			// 16:16 far pointer to an 8-bit signed
			case 0x0210:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.getSignedCharType());
				break;
			// 16:16 huge pointer to an 8-bit signed
			case 0x0310:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.getSignedCharType());
				break;
			// 32-bit pointer to an 8-bit signed
			case 0x0410:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.getSignedCharType());
				break;
			// 16:32 pointer to an 8-bit signed
			case 0x0510:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.getSignedCharType());
				break;
			// 64-bit pointer to an 8-bit signed
			case 0x0610:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.getSignedCharType());
				break;
			// 128-bit near pointer to an 8-bit signed (LLVM doc on 0x0700)
			case 0x0710:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.getSignedCharType());
				break;

			//=======================================
			// Unsigned Character types
			//=======================================
			// 8-bit unsigned 
			case 0x0020:
				primitiveDataType = primitiveApplicator.getUnsignedCharType();
				break;
			// 16-bit pointer to an 8-bit unsigned
			case 0x0120:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.getUnsignedCharType());
				break;
			// 16:16 far pointer to an 8-bit unsigned
			case 0x0220:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.getUnsignedCharType());
				break;
			// 16:16 huge pointer to an 8-bit unsigned
			case 0x0320:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.getUnsignedCharType());
				break;
			// 32-bit pointer to an 8-bit unsigned
			case 0x0420:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.getUnsignedCharType());
				break;
			// 16:32 pointer to an 8-bit unsigned
			case 0x0520:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.getUnsignedCharType());
				break;
			// 64-bit pointer to an 8-bit unsigned
			case 0x0620:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.getUnsignedCharType());
				break;
			// 128-bit near pointer to an 8-bit unsigned (LLVM doc on 0x0700)
			case 0x0720:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.getUnsignedCharType());
				break;

			//=======================================
			// Real character types
			//=======================================
			// a real char
			case 0x0070:
				primitiveDataType = primitiveApplicator.getCharType();
				break;
			// 16-bit pointer to a real char
			case 0x0170:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.getCharType());
				break;
			// 16:16 far pointer to a real char
			case 0x0270:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.getCharType());
				break;
			// 16:16 huge pointer to a real char
			case 0x0370:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.getCharType());
				break;
			// 32-bit pointer to a real char
			case 0x0470:
				primitiveDataType =
					primitiveApplicator.get32PointerType(type, primitiveApplicator.getCharType());
				break;
			// 16:32 pointer to a real char
			case 0x0570:
				primitiveDataType =
					primitiveApplicator.get1632PointerType(type, primitiveApplicator.getCharType());
				break;
			// 64-bit pointer to a real char
			case 0x0670:
				primitiveDataType =
					primitiveApplicator.get64PointerType(type, primitiveApplicator.getCharType());
				break;
			// 128-bit near pointer to a real char (LLVM doc on 0x0700)
			case 0x0770:
				primitiveDataType =
					primitiveApplicator.get128PointerType(type, primitiveApplicator.getCharType());
				break;

			//=======================================
			// Really a wide character types
			//=======================================
			// wide char
			case 0x0071:
				primitiveDataType = primitiveApplicator.getWideCharType();
				break;
			// 16-bit pointer to a wide char
			case 0x0171:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.getWideCharType());
				break;
			// 16:16 far pointer to a wide char
			case 0x0271:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.getWideCharType());
				break;
			// 16:16 huge pointer to a wide char
			case 0x0371:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.getWideCharType());
				break;
			// 32-bit pointer to a wide char
			case 0x0471:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.getWideCharType());
				break;
			// 16:32 pointer to a wide char
			case 0x0571:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.getWideCharType());
				break;
			// 64-bit pointer to a wide char
			case 0x0671:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.getWideCharType());
				break;
			// 128-bit near pointer to a wide char (LLVM doc on 0x0700)
			case 0x0771:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.getWideCharType());
				break;

			//=======================================
			// 16-bit char types
			//=======================================
			// 16-bit unicode char
			case 0x007a:
				primitiveDataType = primitiveApplicator.getUnicode16Type();
				break;
			// 16-bit pointer to a 16-bit unicode char 
			case 0x017a:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.getUnicode16Type());
				break;
			// 16:16 far pointer to a 16-bit unicode char
			case 0x027a:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.getUnicode16Type());
				break;
			// 16:16 huge pointer to a 16-bit unicode char
			case 0x037a:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.getUnicode16Type());
				break;
			// 32-bit pointer to a 16-bit unicode char
			case 0x047a:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.getUnicode16Type());
				break;
			// 16:32 pointer to a 16-bit unicode char
			case 0x057a:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.getUnicode16Type());
				break;
			// 64-bit pointer to a 16-bit unicode char
			case 0x067a:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.getUnicode16Type());
				break;
			// 128-bit near pointer to a 16-bit unicode char (LLVM doc on 0x0700)
			case 0x077a:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.getUnicode16Type());
				break;

			//=======================================
			// 32-bit unicode char types
			//=======================================
			// 32-bit unicode char
			case 0x007b:
				primitiveDataType = primitiveApplicator.getUnicode32Type();
				break;
			// 16-bit pointer to a 32-bit unicode char 
			case 0x017b:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.getUnicode32Type());
				break;
			// 16:16 far pointer to a 32-bit unicode char
			case 0x027b:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.getUnicode32Type());
				break;
			// 16:16 huge pointer to a 32-bit unicode char
			case 0x037b:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.getUnicode32Type());
				break;
			// 32-bit pointer to a 32-bit unicode char
			case 0x047b:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.getUnicode32Type());
				break;
			// 16:32 pointer to a 32-bit unicode char
			case 0x057b:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.getUnicode32Type());
				break;
			// 64-bit pointer to a 32-bit unicode char
			case 0x067b:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.getUnicode32Type());
				break;
			// 128-bit near pointer to a 32-bit unicode char (LLVM doc on 0x0700)
			case 0x077b:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.getUnicode32Type());
				break;

			//=======================================
			// 8-bit int types
			//=======================================
			// 8-bit int
			case 0x0068:
				primitiveDataType = primitiveApplicator.get8BitIntegerType();
				break;
			// 16-bit pointer to an 8-bit int
			case 0x0168:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get8BitIntegerType());
				break;
			// 16:16 far pointer to an 8-bit int
			case 0x0268:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get8BitIntegerType());
				break;
			// 16:16 huge pointer to an 8-bit int
			case 0x0368:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get8BitIntegerType());
				break;
			// 32-bit pointer to an 8-bit int
			case 0x0468:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get8BitIntegerType());
				break;
			// 16:32 pointer to an 8-bit int
			case 0x0568:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get8BitIntegerType());
				break;
			// 64-bit pointer to an 8-bit int
			case 0x0668:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get8BitIntegerType());
				break;
			// 128-bit near pointer to an 8-bit int (LLVM doc on 0x0700)
			case 0x0768:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get8BitIntegerType());
				break;

			//=======================================
			// 8-bit unsigned int types
			//=======================================
			// 8-bit unsigned int
			case 0x0069:
				primitiveDataType = primitiveApplicator.get8BitUnsignedIntegerType();
				break;
			// 16-bit pointer to an 8-bit unsigned int
			case 0x0169:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get8BitUnsignedIntegerType());
				break;
			// 16:16 far pointer to an 8-bit unsigned int
			case 0x0269:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get8BitUnsignedIntegerType());
				break;
			// 16:16 huge pointer to an 8-bit unsigned int
			case 0x0369:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get8BitUnsignedIntegerType());
				break;
			// 32-bit pointer to an 8-bit unsigned int
			case 0x0469:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get8BitUnsignedIntegerType());
				break;
			// 16:32 pointer to an 8-bit unsigned int
			case 0x0569:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get8BitUnsignedIntegerType());
				break;
			// 64-bit pointer to an 8-bit unsigned int
			case 0x0669:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get8BitUnsignedIntegerType());
				break;
			// 128-bit near pointer to an 8-bit unsigned int (LLVM doc on 0x0700)
			case 0x0769:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get8BitUnsignedIntegerType());
				break;

			//=======================================
			// 16-bit short types
			//=======================================
			// 16-bit signed short
			case 0x0011:
				primitiveDataType = primitiveApplicator.get16BitShortType();
				break;
			// 16-bit pointer to a 16-bit signed short
			case 0x0111:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get16BitShortType());
				break;
			// 16:16 far pointer to a 16-bit signed short
			case 0x0211:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get16BitShortType());
				break;
			// 16:16 huge pointer to a 16-bit signed short
			case 0x0311:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get16BitShortType());
				break;
			// 32-bit pointer to a 16-bit signed short
			case 0x0411:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get16BitShortType());
				break;
			// 16:32 pointer to a 16-bit signed short
			case 0x0511:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get16BitShortType());
				break;
			// 64-bit pointer to a 16-bit signed short
			case 0x0611:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get16BitShortType());
				break;
			// 128-bit near pointer to a 16-bit signed short (LLVM doc on 0x0700)
			case 0x0711:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get16BitShortType());
				break;

			//=======================================
			// 16-bit unsigned short types
			//=======================================
			// 16-bit unsigned signed short
			case 0x0021:
				primitiveDataType = primitiveApplicator.get16BitUnsignedShortType();
				break;
			// 16-bit pointer to a 16-bit unsigned signed short
			case 0x0121:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get16BitUnsignedShortType());
				break;
			// 16:16 far pointer to a 16-bit unsigned signed short
			case 0x0221:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get16BitUnsignedShortType());
				break;
			// 16:16 huge pointer to a 16-bit unsigned signed short
			case 0x0321:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get16BitUnsignedShortType());
				break;
			// 32-bit pointer to a 16-bit unsigned signed short
			case 0x0421:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get16BitUnsignedShortType());
				break;
			// 16:32 pointer to a 16-bit unsigned signed short
			case 0x0521:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get16BitUnsignedShortType());
				break;
			// 64-bit pointer to a 16-bit unsigned signed short
			case 0x0621:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get16BitUnsignedShortType());
				break;
			// 128-bit near pointer to a 16-bit unsigned signed short (LLVM doc on 0x0700)
			case 0x0721:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get16BitUnsignedShortType());
				break;

			//=======================================
			// 16-bit signed int types
			//=======================================
			// 16-bit signed int
			case 0x0072:
				primitiveDataType = primitiveApplicator.get16BitIntegerType();
				break;
			// 16-bit pointer to a 16-bit signed int
			case 0x0172:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get16BitIntegerType());
				break;
			// 16:16 far pointer to a 16-bit signed int
			case 0x0272:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get16BitIntegerType());
				break;
			// 16:16 huge pointer to a 16-bit signed int
			case 0x0372:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get16BitIntegerType());
				break;
			// 32-bit pointer to a 16-bit signed int
			case 0x0472:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get16BitIntegerType());
				break;
			// 16:32 pointer to a 16-bit signed int
			case 0x0572:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get16BitIntegerType());
				break;
			// 64-bit pointer to a 16-bit signed int
			case 0x0672:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get16BitIntegerType());
				break;
			// 128-bit near pointer to a 16-bit signed int (LLVM doc on 0x0700)
			case 0x0772:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get16BitIntegerType());
				break;

			//=======================================
			// 16-bit unsigned int types
			//=======================================
			// 16-bit unsigned int
			case 0x0073:
				primitiveDataType = primitiveApplicator.get16BitUnsignedIntegerType();
				break;
			// 16-bit pointer to a 16-bit unsigned int
			case 0x0173:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get16BitUnsignedIntegerType());
				break;
			// 16:16 far pointer to a 16-bit unsigned int
			case 0x0273:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get16BitUnsignedIntegerType());
				break;
			// 16:16 huge pointer to a 16-bit unsigned int
			case 0x0373:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get16BitUnsignedIntegerType());
				break;
			// 32-bit pointer to a 16-bit unsigned int
			case 0x0473:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get16BitUnsignedIntegerType());
				break;
			// 16:32 pointer to a 16-bit unsigned int
			case 0x0573:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get16BitUnsignedIntegerType());
				break;
			// 64-bit pointer to a 16-bit unsigned int
			case 0x0673:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get16BitUnsignedIntegerType());
				break;
			// 128-bit near pointer to a 16-bit unsigned int (LLVM doc on 0x0700)
			case 0x0773:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get16BitUnsignedIntegerType());
				break;

			//=======================================
			// 32-bit long types
			//=======================================
			// 32-bit signed long
			case 0x0012:
				primitiveDataType = primitiveApplicator.get32BitLongType();
				break;
			// 16-bit pointer to a 32-bit signed long
			case 0x0112:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get32BitLongType());
				break;
			// 16:16 far pointer to a 32-bit signed long
			case 0x0212:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get32BitLongType());
				break;
			// 16:16 huge pointer to a 32-bit signed long
			case 0x0312:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get32BitLongType());
				break;
			// 32-bit pointer to a 32-bit signed long
			case 0x0412:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get32BitLongType());
				break;
			// 16:32 pointer to a 32-bit signed long
			case 0x0512:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get32BitLongType());
				break;
			// 64-bit pointer to a 32-bit signed long
			case 0x0612:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get32BitLongType());
				break;
			// 128-bit near pointer to a 32-bit signed long (LLVM doc on 0x0700)
			case 0x0712:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get32BitLongType());
				break;

			//=======================================
			// 32-bit unsigned long types
			//=======================================
			// 32-bit unsigned signed long
			case 0x0022:
				primitiveDataType = primitiveApplicator.get32BitUnsignedLongType();
				break;
			// 16-bit pointer to a 32-bit unsigned signed long
			case 0x0122:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get32BitUnsignedLongType());
				break;
			// 16:16 far pointer to a 32-bit unsigned signed long
			case 0x0222:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get32BitUnsignedLongType());
				break;
			// 16:16 huge pointer to a 32-bit unsigned signed long
			case 0x0322:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get32BitUnsignedLongType());
				break;
			// 32-bit pointer to a 32-bit unsigned signed long
			case 0x0422:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get32BitUnsignedLongType());
				break;
			// 16:32 pointer to a 32-bit unsigned signed long
			case 0x0522:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get32BitUnsignedLongType());
				break;
			// 64-bit pointer to a 32-bit unsigned signed long
			case 0x0622:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get32BitUnsignedLongType());
				break;
			// 128-bit near pointer to a 32-bit unsigned signed long (LLVM doc on 0x0700)
			case 0x0722:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get32BitUnsignedLongType());
				break;

			//=======================================
			// 32-bit signed int types
			//=======================================
			// 32-bit signed int
			case 0x0074:
				primitiveDataType = primitiveApplicator.get32BitIntegerType();
				break;
			// 16-bit pointer to a 32-bit signed int
			case 0x0174:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get32BitIntegerType());
				break;
			// 16:16 far pointer to a 32-bit signed int
			case 0x0274:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get32BitIntegerType());
				break;
			// 16:16 huge pointer to a 32-bit signed int
			case 0x0374:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get32BitIntegerType());
				break;
			// 32-bit pointer to a 32-bit signed int
			case 0x0474:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get32BitIntegerType());
				break;
			// 16:32 pointer to a 32-bit signed int
			case 0x0574:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get32BitIntegerType());
				break;
			// 64-bit pointer to a 32-bit signed int
			case 0x0674:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get32BitIntegerType());
				break;
			// 128-bit near pointer to a 32-bit signed int (LLVM doc on 0x0700)
			case 0x0774:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get32BitIntegerType());
				break;

			//=======================================
			// 32-bit unsigned int types
			//=======================================
			// 32-bit unsigned int
			case 0x0075:
				primitiveDataType = primitiveApplicator.get32BitUnsignedIntegerType();
				break;
			// 16-bit pointer to a 32-bit unsigned int
			case 0x0175:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get32BitUnsignedIntegerType());
				break;
			// 16:16 far pointer to a 32-bit unsigned int
			case 0x0275:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get32BitUnsignedIntegerType());
				break;
			// 16:16 huge pointer to a 32-bit unsigned int
			case 0x0375:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get32BitUnsignedIntegerType());
				break;
			// 32-bit pointer to a 32-bit unsigned int
			case 0x0475:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get32BitUnsignedIntegerType());
				break;
			// 16:32 pointer to a 32-bit unsigned int
			case 0x0575:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get32BitUnsignedIntegerType());
				break;
			// 64-bit pointer to a 32-bit unsigned int
			case 0x0675:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get32BitUnsignedIntegerType());
				break;
			// 128-bit near pointer to a 32-bit unsigned int (LLVM doc on 0x0700)
			case 0x0775:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get32BitUnsignedIntegerType());
				break;

			//=======================================
			// 64-bit quad types
			//=======================================
			// 64-bit signed long
			case 0x0013:
				primitiveDataType = primitiveApplicator.get64BitLongType();
				break;
			// 16-bit pointer to a 64-bit signed long
			case 0x0113:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get64BitLongType());
				break;
			// 16:16 far pointer to a 64-bit signed long
			case 0x0213:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get64BitLongType());
				break;
			// 16:16 huge pointer to a 64-bit signed long
			case 0x0313:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get64BitLongType());
				break;
			// 32-bit pointer to a 64-bit signed long
			case 0x0413:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get64BitLongType());
				break;
			// 16:32 pointer to a 64-bit signed long
			case 0x0513:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get64BitLongType());
				break;
			// 64-bit pointer to a 64-bit signed long
			case 0x0613:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get64BitLongType());
				break;
			// 128-bit near pointer to a 64-bit signed long (LLVM doc on 0x0700)
			case 0x0713:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get64BitLongType());
				break;

			//=======================================
			// 64-bit unsigned quad types
			//=======================================
			// 64-bit unsigned signed long
			case 0x0023:
				primitiveDataType = primitiveApplicator.get64BitUnsignedLongType();
				break;
			// 16-bit pointer to a 64-bit unsigned signed long
			case 0x0123:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get64BitUnsignedLongType());
				break;
			// 16:16 far pointer to a 64-bit unsigned signed long
			case 0x0223:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get64BitUnsignedLongType());
				break;
			// 16:16 huge pointer to a 64-bit unsigned signed long
			case 0x0323:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get64BitUnsignedLongType());
				break;
			// 32-bit pointer to a 64-bit unsigned signed long
			case 0x0423:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get64BitUnsignedLongType());
				break;
			// 16:32 pointer to a 64-bit unsigned signed long
			case 0x0523:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get64BitUnsignedLongType());
				break;
			// 64-bit pointer to a 64-bit unsigned signed long
			case 0x0623:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get64BitUnsignedLongType());
				break;
			// 128-bit near pointer to a 64-bit unsigned signed long (LLVM doc on 0x0700)
			case 0x0723:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get64BitUnsignedLongType());
				break;

			//=======================================
			// 64-bit signed int types
			//=======================================
			// 64-bit signed int
			case 0x0076:
				primitiveDataType = primitiveApplicator.get64BitIntegerType();
				break;
			// 16-bit pointer to a 64-bit signed int
			case 0x0176:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get64BitIntegerType());
				break;
			// 16:16 far pointer to a 64-bit signed int
			case 0x0276:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get64BitIntegerType());
				break;
			// 16:16 huge pointer to a 64-bit signed int
			case 0x0376:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get64BitIntegerType());
				break;
			// 32-bit pointer to a 64-bit signed int
			case 0x0476:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get64BitIntegerType());
				break;
			// 16:32 pointer to a 64-bit signed int
			case 0x0576:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get64BitIntegerType());
				break;
			// 64-bit pointer to a 64-bit signed int
			case 0x0676:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get64BitIntegerType());
				break;
			// 128-bit near pointer to a 64-bit signed int (LLVM doc on 0x0700)
			case 0x0776:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get64BitIntegerType());
				break;

			//=======================================
			// 64-bit unsigned int types
			//=======================================
			// 64-bit unsigned int
			case 0x0077:
				primitiveDataType = primitiveApplicator.get64BitUnsignedIntegerType();
				break;
			// 16-bit pointer to a 64-bit unsigned int
			case 0x0177:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get64BitUnsignedIntegerType());
				break;
			// 16:16 far pointer to a 64-bit unsigned int
			case 0x0277:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get64BitUnsignedIntegerType());
				break;
			// 16:16 huge pointer to a 64-bit unsigned int
			case 0x0377:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get64BitUnsignedIntegerType());
				break;
			// 32-bit pointer to a 64-bit unsigned int
			case 0x0477:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get64BitUnsignedIntegerType());
				break;
			// 16:32 pointer to a 64-bit unsigned int
			case 0x0577:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get64BitUnsignedIntegerType());
				break;
			// 64-bit pointer to a 64-bit unsigned int
			case 0x0677:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get64BitUnsignedIntegerType());
				break;
			// 128-bit near pointer to a 64-bit unsigned int (LLVM doc on 0x0700)
			case 0x0777:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get64BitUnsignedIntegerType());
				break;

			//=======================================
			// 128-bit octet types
			//=======================================
			// 128-bit signed long
			case 0x0014:
				primitiveDataType = primitiveApplicator.get128BitLongType();
				break;
			// 16-bit pointer to a 128-bit signed long
			case 0x0114:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get128BitLongType());
				break;
			// 16:16 far pointer to a 128-bit signed long
			case 0x0214:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get128BitLongType());
				break;
			// 16:16 huge pointer to a 128-bit signed long
			case 0x0314:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get128BitLongType());
				break;
			// 32-bit pointer to a 128-bit signed long
			case 0x0414:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get128BitLongType());
				break;
			// 16:32 pointer to a 128-bit signed long
			case 0x0514:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get128BitLongType());
				break;
			// 64-bit pointer to a 128-bit signed long
			case 0x0614:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get128BitLongType());
				break;
			// 128-bit near pointer to a 128-bit signed long (LLVM doc on 0x0700)
			case 0x0714:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get128BitLongType());
				break;

			//=======================================
			// 128-bit unsigned octet types
			//=======================================
			// 128-bit unsigned signed long
			case 0x0024:
				primitiveDataType = primitiveApplicator.get128BitUnsignedLongType();
				break;
			// 16-bit pointer to a 128-bit unsigned signed long
			case 0x0124:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get128BitUnsignedLongType());
				break;
			// 16:16 far pointer to a 128-bit unsigned signed long
			case 0x0224:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get128BitUnsignedLongType());
				break;
			// 16:16 huge pointer to a 128-bit unsigned signed long
			case 0x0324:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get128BitUnsignedLongType());
				break;
			// 32-bit pointer to a 128-bit unsigned signed long
			case 0x0424:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get128BitUnsignedLongType());
				break;
			// 16:32 pointer to a 128-bit unsigned signed long
			case 0x0524:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get128BitUnsignedLongType());
				break;
			// 64-bit pointer to a 128-bit unsigned signed long
			case 0x0624:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get128BitUnsignedLongType());
				break;
			// 128-bit near pointer to a 128-bit unsigned signed long (LLVM doc on 0x0700)
			case 0x0724:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get128BitUnsignedLongType());
				break;

			//=======================================
			// 128-bit signed int types
			//=======================================
			// 128-bit signed int
			case 0x0078:
				primitiveDataType = primitiveApplicator.get128BitIntegerType();
				break;
			// 16-bit pointer to a 128-bit signed int
			case 0x0178:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get128BitIntegerType());
				break;
			// 16:16 far pointer to a 128-bit signed int
			case 0x0278:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get128BitIntegerType());
				break;
			// 16:16 huge pointer to a 128-bit signed int
			case 0x0378:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get128BitIntegerType());
				break;
			// 32-bit pointer to a 128-bit signed int
			case 0x0478:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get128BitIntegerType());
				break;
			// 16:32 pointer to a 128-bit signed int
			case 0x0578:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get128BitIntegerType());
				break;
			// 64-bit pointer to a 128-bit signed int
			case 0x0678:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get128BitIntegerType());
				break;
			// 128-bit near pointer to a 128-bit signed int (LLVM doc on 0x0700)
			case 0x0778:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get128BitIntegerType());
				break;

			//=======================================
			// 128-bit unsigned int types
			//=======================================
			// 128-bit unsigned int
			case 0x0079:
				primitiveDataType = primitiveApplicator.get128BitUnsignedIntegerType();
				break;
			// 16-bit pointer to a 128-bit unsigned int
			case 0x0179:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get128BitUnsignedIntegerType());
				break;
			// 16:16 far pointer to a 128-bit unsigned int
			case 0x0279:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get128BitUnsignedIntegerType());
				break;
			// 16:16 huge pointer to a 128-bit unsigned int
			case 0x0379:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get128BitUnsignedIntegerType());
				break;
			// 32-bit pointer to a 128-bit unsigned int
			case 0x0479:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get128BitUnsignedIntegerType());
				break;
			// 16:32 pointer to a 128-bit unsigned int
			case 0x0579:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get128BitUnsignedIntegerType());
				break;
			// 64-bit pointer to a 128-bit unsigned int
			case 0x0679:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get128BitUnsignedIntegerType());
				break;
			// 128-bit near pointer to a 128-bit unsigned int (LLVM doc on 0x0700)
			case 0x0779:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get128BitUnsignedIntegerType());
				break;

			//=======================================
			// 16-bit real types
			//=======================================
			// 16-bit real
			case 0x0046:
				primitiveDataType = primitiveApplicator.get16BitRealType();
				break;
			// 16-bit pointer to a 16-bit real
			case 0x0146:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get16BitRealType());
				break;
			// 16:16 far pointer to a 16-bit real
			case 0x0246:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get16BitRealType());
				break;
			// 16:16 huge pointer to a 16-bit real
			case 0x0346:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get16BitRealType());
				break;
			// 32-bit pointer to a 16-bit real
			case 0x0446:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get16BitRealType());
				break;
			// 16:32 pointer to a 16-bit real
			case 0x0546:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get16BitRealType());
				break;
			// 64-bit pointer to a 16-bit real
			case 0x0646:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get16BitRealType());
				break;
			// 128-bit near pointer to a 16-bit real (LLVM doc on 0x0700)
			case 0x0746:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get16BitRealType());
				break;

			//=======================================
			// 32-bit real types
			//=======================================
			// 32-bit real
			case 0x0040:
				primitiveDataType = primitiveApplicator.get32BitRealType();
				break;
			// 16-bit pointer to a 32-bit real
			case 0x0140:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get32BitRealType());
				break;
			// 16:16 far pointer to a 32-bit real
			case 0x0240:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get32BitRealType());
				break;
			// 16:16 huge pointer to a 32-bit real
			case 0x0340:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get32BitRealType());
				break;
			// 32-bit pointer to a 32-bit real
			case 0x0440:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get32BitRealType());
				break;
			// 16:32 pointer to a 32-bit real
			case 0x0540:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get32BitRealType());
				break;
			// 64-bit pointer to a 32-bit real
			case 0x0640:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get32BitRealType());
				break;
			// 128-bit near pointer to a 32-bit real (LLVM doc on 0x0700)
			case 0x0740:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get32BitRealType());
				break;

			//=======================================
			// 32-bit partial-precision real types
			//=======================================
			// 32-bit partial-precision real
			case 0x0045:
				primitiveDataType = primitiveApplicator.get32BitPartialPrecisionRealType();
				break;
			// 16-bit pointer to a 32-bit partial-precision real
			case 0x0145:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get32BitPartialPrecisionRealType());
				break;
			// 16:16 far pointer to a 32-bit partial-precision real
			case 0x0245:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get32BitPartialPrecisionRealType());
				break;
			// 16:16 huge pointer to a 32-bit partial-precision real
			case 0x0345:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get32BitPartialPrecisionRealType());
				break;
			// 32-bit pointer to a 32-bit partial-precision real
			case 0x0445:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get32BitPartialPrecisionRealType());
				break;
			// 16:32 pointer to a 32-bit partial-precision real
			case 0x0545:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get32BitPartialPrecisionRealType());
				break;
			// 64-bit pointer to a 32-bit partial-precision real
			case 0x0645:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get32BitPartialPrecisionRealType());
				break;
			// 128-bit near pointer to a 32-bit partial-precision real (LLVM doc on 0x0700)
			case 0x0745:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get32BitPartialPrecisionRealType());
				break;

			//=======================================
			// 48-bit real types
			//=======================================
			// 48-bit real
			case 0x0044:
				primitiveDataType = primitiveApplicator.get48BitRealType();
				break;
			// 16-bit pointer to a 48-bit real
			case 0x0144:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get48BitRealType());
				break;
			// 16:16 far pointer to a 48-bit real
			case 0x0244:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get48BitRealType());
				break;
			// 16:16 huge pointer to a 48-bit real
			case 0x0344:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get48BitRealType());
				break;
			// 32-bit pointer to a 48-bit real
			case 0x0444:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get48BitRealType());
				break;
			// 16:32 pointer to a 48-bit real
			case 0x0544:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get48BitRealType());
				break;
			// 64-bit pointer to a 48-bit real
			case 0x0644:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get48BitRealType());
				break;
			// 128-bit near pointer to a 48-bit real (LLVM doc on 0x0700)
			case 0x0744:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get48BitRealType());
				break;

			//=======================================
			// 64-bit real types
			//=======================================
			// 64-bit real
			case 0x0041:
				primitiveDataType = primitiveApplicator.get64BitRealType();
				break;
			// 16-bit pointer to a 64-bit real
			case 0x0141:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get64BitRealType());
				break;
			// 16:16 far pointer to a 64-bit real
			case 0x0241:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get64BitRealType());
				break;
			// 16:16 huge pointer to a 64-bit real
			case 0x0341:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get64BitRealType());
				break;
			// 32-bit pointer to a 64-bit real
			case 0x0441:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get64BitRealType());
				break;
			// 16:32 pointer to a 64-bit real
			case 0x0541:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get64BitRealType());
				break;
			// 64-bit pointer to a 64-bit real
			case 0x0641:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get64BitRealType());
				break;
			// 128-bit near pointer to a 64-bit real (LLVM doc on 0x0700)
			case 0x0741:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get64BitRealType());
				break;

			//=======================================
			// 80-bit real types
			//=======================================
			// 80-bit real
			case 0x0042:
				primitiveDataType = primitiveApplicator.get80BitRealType();
				break;
			// 16-bit pointer to an 80-bit real
			case 0x0142:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get80BitRealType());
				break;
			// 16:16 far pointer to an 80-bit real
			case 0x0242:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get80BitRealType());
				break;
			// 16:16 huge pointer to an 80-bit real
			case 0x0342:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get80BitRealType());
				break;
			// 32-bit pointer to an 80-bit real
			case 0x0442:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get80BitRealType());
				break;
			// 16:32 pointer to an 80-bit real
			case 0x0542:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get80BitRealType());
				break;
			// 64-bit pointer to an 80-bit real
			case 0x0642:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get80BitRealType());
				break;
			// 128-bit near pointer to an 80-bit real (LLVM doc on 0x0700)
			case 0x0742:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get80BitRealType());
				break;

			//=======================================
			// 128-bit real types
			//=======================================
			// 128-bit real
			case 0x0043:
				primitiveDataType = primitiveApplicator.get128BitRealType();
				break;
			// 16-bit pointer to a 128-bit real
			case 0x0143:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get128BitRealType());
				break;
			// 16:16 far pointer to a 128-bit real
			case 0x0243:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get128BitRealType());
				break;
			// 16:16 huge pointer to a 128-bit real
			case 0x0343:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get128BitRealType());
				break;
			// 32-bit pointer to a 128-bit real
			case 0x0443:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get128BitRealType());
				break;
			// 16:32 pointer to a 128-bit real
			case 0x0543:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get128BitRealType());
				break;
			// 64-bit pointer to a 128-bit real
			case 0x0643:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get128BitRealType());
				break;
			// 128-bit near pointer to a 128-bit real (LLVM doc on 0x0700)
			case 0x0743:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get128BitRealType());
				break;

			//=======================================
			// 32-bit complex types
			//=======================================
			// 32-bit complex
			case 0x0050:
				primitiveDataType = primitiveApplicator.get32BitComplexType();
				break;
			// 16-bit pointer to a 32-bit complex
			case 0x0150:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get32BitComplexType());
				break;
			// 16:16 far pointer to a 32-bit complex
			case 0x0250:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get32BitComplexType());
				break;
			// 16:16 huge pointer to a 32-bit complex
			case 0x0350:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get32BitComplexType());
				break;
			// 32-bit pointer to an 32-bit complex
			case 0x0450:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get32BitComplexType());
				break;
			// 16:32 pointer to an 32-bit complex
			case 0x0550:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get32BitComplexType());
				break;
			// 64-bit pointer to an 32-bit complex
			case 0x0650:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get32BitComplexType());
				break;
			// 128-bit near pointer to an 32-bit complex (LLVM doc on 0x0700)
			case 0x0750:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get32BitComplexType());
				break;

			//=======================================
			// 64-bit complex types
			//=======================================
			// 64-bit complex
			case 0x0051:
				primitiveDataType = primitiveApplicator.get64BitComplexType();
				break;
			// 16-bit pointer to a 64-bit complex
			case 0x0151:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get64BitComplexType());
				break;
			// 16:16 far pointer to a 64-bit complex
			case 0x0251:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get64BitComplexType());
				break;
			// 16:16 huge pointer to a 64-bit complex
			case 0x0351:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get64BitComplexType());
				break;
			// 32-bit pointer to a 64-bit complex
			case 0x0451:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get64BitComplexType());
				break;
			// 16:32 pointer to a 64-bit complex
			case 0x0551:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get64BitComplexType());
				break;
			// 64-bit pointer to a 64-bit complex
			case 0x0651:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get64BitComplexType());
				break;
			// 128-bit near pointer to a 64-bit complex (LLVM doc on 0x0700)
			case 0x0751:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get64BitComplexType());
				break;

			//=======================================
			// 80-bit complex types
			//=======================================
			// 80-bit complex
			case 0x0052:
				primitiveDataType = primitiveApplicator.get80BitComplexType();
				break;
			// 16-bit pointer to an 80-bit complex
			case 0x0152:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get80BitComplexType());
				break;
			// 16:16 far pointer to an 80-bit complex
			case 0x0252:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get80BitComplexType());
				break;
			// 16:16 huge pointer to an 80-bit complex
			case 0x0352:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get80BitComplexType());
				break;
			// 32-bit pointer to an 80-bit complex
			case 0x0452:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get80BitComplexType());
				break;
			// 16:32 pointer to an 80-bit complex
			case 0x0552:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get80BitComplexType());
				break;
			// 64-bit pointer to an 80-bit complex
			case 0x0652:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get80BitComplexType());
				break;
			// 128-bit near pointer to an 80-bit complex (LLVM doc on 0x0700)
			case 0x0752:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get80BitComplexType());
				break;

			//=======================================
			// 128-bit complex types
			//=======================================
			// 128-bit complex
			case 0x0053:
				primitiveDataType = primitiveApplicator.get128BitComplexType();
				break;
			// 16-bit pointer to a 128-bit complex
			case 0x0153:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get128BitComplexType());
				break;
			// 16:16 far pointer to a 128-bit complex
			case 0x0253:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get128BitComplexType());
				break;
			// 16:16 huge pointer to a 128-bit complex
			case 0x0353:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get128BitComplexType());
				break;
			// 32-bit pointer to a 128-bit complex
			case 0x0453:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get128BitComplexType());
				break;
			// 16:32 pointer to a 128-bit complex
			case 0x0553:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get128BitComplexType());
				break;
			// 64-bit pointer to a 128-bit complex
			case 0x0653:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get128BitComplexType());
				break;
			// 128-bit near pointer to a 128-bit complex (LLVM doc on 0x0700)
			case 0x0753:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get128BitComplexType());
				break;

			//=======================================
			// 48-bit complex types
			//=======================================
			// 48-bit complex
			case 0x0054:
				primitiveDataType = primitiveApplicator.get48BitComplexType();
				break;
			// 16-bit pointer to a 48-bit complex
			case 0x0154:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get48BitComplexType());
				break;
			// 16:16 far pointer to a 48-bit complex
			case 0x0254:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get48BitComplexType());
				break;
			// 16:16 huge pointer to a 48-bit complex
			case 0x0354:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get48BitComplexType());
				break;
			// 32-bit pointer to a 48-bit complex
			case 0x0454:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get48BitComplexType());
				break;
			// 16:32 pointer to a 48-bit complex
			case 0x0554:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get48BitComplexType());
				break;
			// 64-bit pointer to a 48-bit complex
			case 0x0654:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get48BitComplexType());
				break;
			// 128-bit near pointer to a 48-bit complex (LLVM doc on 0x0700)
			case 0x0754:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get48BitComplexType());
				break;

			//=======================================
			// 32-bit partial-precision complex types
			//=======================================
			// 32-bit partial-precision complex
			case 0x0055:
				primitiveDataType = primitiveApplicator.get32BitPartialPrecisionComplexType();
				break;
			// 16-bit pointer to a 32-bit partial-precision complex
			case 0x0155:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get32BitPartialPrecisionComplexType());
				break;
			// 16:16 far pointer to a 32-bit partial-precision complex
			case 0x0255:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get32BitPartialPrecisionComplexType());
				break;
			// 16:16 huge pointer to a 32-bit partial-precision complex
			case 0x0355:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get32BitPartialPrecisionComplexType());
				break;
			// 32-bit pointer to a 32-bit partial-precision complex
			case 0x0455:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get32BitPartialPrecisionComplexType());
				break;
			// 16:32 pointer to a 32-bit partial-precision complex
			case 0x0555:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get32BitPartialPrecisionComplexType());
				break;
			// 64-bit pointer to a 32-bit partial-precision complex
			case 0x0655:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get32BitPartialPrecisionComplexType());
				break;
			// 128-bit near pointer to a 32-bit partial-precision complex (LLVM doc on 0x0700)
			case 0x0755:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get32BitPartialPrecisionComplexType());
				break;

			//=======================================
			// 16-bit complex types
			//=======================================
			// 16-bit complex
			case 0x0056:
				primitiveDataType = primitiveApplicator.get16BitComplexType();
				break;
			// 16-bit pointer to a 16-bit complex
			case 0x0156:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get16BitComplexType());
				break;
			// 16:16 far pointer to a 16-bit complex
			case 0x0256:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get16BitComplexType());
				break;
			// 16:16 huge pointer to a 16-bit complex
			case 0x0356:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get16BitComplexType());
				break;
			// 32-bit pointer to a 16-bit complex
			case 0x0456:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get16BitComplexType());
				break;
			// 16:32 pointer to a 16-bit complex
			case 0x0556:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get16BitComplexType());
				break;
			// 64-bit pointer to a 16-bit complex
			case 0x0656:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get16BitComplexType());
				break;
			// 128-bit near pointer to a 16-bit complex (LLVM doc on 0x0700)
			case 0x0756:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get16BitComplexType());
				break;

			//=======================================
			// 8-bit boolean types
			//=======================================
			// 8-bit boolean
			case 0x0030:
				primitiveDataType = primitiveApplicator.get8BitBooleanType();
				break;
			// 16-bit pointer to an 8-bit boolean
			case 0x0130:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get8BitBooleanType());
				break;
			// 16:16 far pointer to an 8-bit boolean
			case 0x0230:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get8BitBooleanType());
				break;
			// 16:16 huge pointer to an 8-bit boolean
			case 0x0330:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get8BitBooleanType());
				break;
			// 32-bit pointer to an 8-bit boolean
			case 0x0430:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get8BitBooleanType());
				break;
			// 16:32 pointer to an 8-bit boolean
			case 0x0530:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get8BitBooleanType());
				break;
			// 64-bit pointer to an 8-bit boolean
			case 0x0630:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get8BitBooleanType());
				break;
			// 128-bit near pointer to an 8-bit boolean (LLVM doc on 0x0700)
			case 0x0730:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get8BitBooleanType());
				break;

			//=======================================
			// 16-bit boolean types
			//=======================================
			// 16-bit boolean
			case 0x0031:
				primitiveDataType = primitiveApplicator.get16BitBooleanType();
				break;
			// 16-bit pointer to a 16-bit boolean
			case 0x0131:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get16BitBooleanType());
				break;
			// 16:16 far pointer to a 16-bit boolean
			case 0x0231:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get16BitBooleanType());
				break;
			// 16:16 huge pointer to a 16-bit boolean
			case 0x0331:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get16BitBooleanType());
				break;
			// 32-bit pointer to a 16-bit boolean
			case 0x0431:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get16BitBooleanType());
				break;
			// 16:32 pointer to a 16-bit boolean
			case 0x0531:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get16BitBooleanType());
				break;
			// 64-bit pointer to a 16-bit boolean
			case 0x0631:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get16BitBooleanType());
				break;
			// 128-bit near pointer to a 16-bit boolean (LLVM doc on 0x0700)
			case 0x0731:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get16BitBooleanType());
				break;

			//=======================================
			// 32-bit boolean types
			//=======================================
			// 32-bit boolean
			case 0x0032:
				primitiveDataType = primitiveApplicator.get32BitBooleanType();
				break;
			// 16-bit pointer to a 32-bit boolean
			case 0x0132:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get32BitBooleanType());
				break;
			// 16:16 far pointer to a 32-bit boolean
			case 0x0232:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get32BitBooleanType());
				break;
			// 16:16 huge pointer to a 32-bit boolean
			case 0x0332:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get32BitBooleanType());
				break;
			// 32-bit pointer to a 32-bit boolean
			case 0x0432:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get32BitBooleanType());
				break;
			// 16:32 pointer to a 32-bit boolean
			case 0x0532:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get32BitBooleanType());
				break;
			// 64-bit pointer to a 32-bit boolean
			case 0x0632:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get32BitBooleanType());
				break;
			// 128-bit near pointer to a 32-bit boolean (LLVM doc on 0x0700)
			case 0x0732:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get32BitBooleanType());
				break;

			//=======================================
			// 64-bit boolean types
			//=======================================
			// 64-bit boolean
			case 0x0033:
				primitiveDataType = primitiveApplicator.get64BitBooleanType();
				break;
			// 16-bit pointer to a 64-bit boolean
			case 0x0133:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get64BitBooleanType());
				break;
			// 16:16 far pointer to a 64-bit boolean
			case 0x0233:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get64BitBooleanType());
				break;
			// 16:16 huge pointer to a 64-bit boolean
			case 0x0333:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get64BitBooleanType());
				break;
			// 32-bit pointer to a 64-bit boolean
			case 0x0433:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get64BitBooleanType());
				break;
			// 16:32 pointer to a 64-bit boolean
			case 0x0533:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get64BitBooleanType());
				break;
			// 64-bit pointer to a 64-bit boolean
			case 0x0633:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get64BitBooleanType());
				break;
			// 128-bit near pointer to a 64-bit boolean (LLVM doc on 0x0700)
			case 0x0733:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get64BitBooleanType());
				break;

			//=======================================
			// 128-bit boolean types
			//=======================================
			// 128-bit boolean
			case 0x0034:
				primitiveDataType = primitiveApplicator.get128BitBooleanType();
				break;
			// 16-bit pointer to a 128-bit boolean
			case 0x0134:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.get128BitBooleanType());
				break;
			// 16:16 far pointer to a 128-bit boolean
			case 0x0234:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.get128BitBooleanType());
				break;
			// 16:16 huge pointer to a 128-bit boolean
			case 0x0334:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.get128BitBooleanType());
				break;
			// 32-bit pointer to a 128-bit boolean
			case 0x0434:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.get128BitBooleanType());
				break;
			// 16:32 pointer to a 128-bit boolean
			case 0x0534:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.get128BitBooleanType());
				break;
			// 64-bit pointer to a 128-bit boolean
			case 0x0634:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.get128BitBooleanType());
				break;
			// 128-bit near pointer to a 128-bit boolean (LLVM doc on 0x0700)
			case 0x0734:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.get128BitBooleanType());
				break;

			//=======================================
			// Internal type with pointers
			//=======================================
			// CV Internal type for created near pointers
			case 0x01f0:
				primitiveDataType = primitiveApplicator.get16NearPointerType(type,
					primitiveApplicator.createTypedefNamedSizedType("CVInternal", 1));
				break;
			// CV Internal type for created far pointers
			case 0x02f0:
				primitiveDataType = primitiveApplicator.get1616FarPointerType(type,
					primitiveApplicator.createTypedefNamedSizedType("CVInternal", 1));
				break;
			// CV Internal type for created huge pointers
			case 0x03f0:
				primitiveDataType = primitiveApplicator.get1616HugePointerType(type,
					primitiveApplicator.createTypedefNamedSizedType("CVInternal", 1));
				break;
			// CV Internal type for created near 32-bit pointers
			case 0x04f0:
				primitiveDataType = primitiveApplicator.get32PointerType(type,
					primitiveApplicator.createTypedefNamedSizedType("CVInternal", 1));
				break;
			// CV Internal type for created far 32-bit pointers
			case 0x05f0:
				primitiveDataType = primitiveApplicator.get1632PointerType(type,
					primitiveApplicator.createTypedefNamedSizedType("CVInternal", 1));
				break;
			// CV Internal type for created near 64-bit pointers
			case 0x06f0:
				primitiveDataType = primitiveApplicator.get64PointerType(type,
					primitiveApplicator.createTypedefNamedSizedType("CVInternal", 1));
				break;
			// CV Internal type for created near 128-bit near pointers (LLVM doc on 0x0700)
			case 0x07f0:
				primitiveDataType = primitiveApplicator.get128PointerType(type,
					primitiveApplicator.createTypedefNamedSizedType("CVInternal", 1));
				break;

			default:
				// Note: 0x0400 seems to have been used as a this pointer type.
				primitiveDataType = primitiveApplicator.createUnmappedPdbType(type);
				break;

		}

		return primitiveDataType;
	}

}
