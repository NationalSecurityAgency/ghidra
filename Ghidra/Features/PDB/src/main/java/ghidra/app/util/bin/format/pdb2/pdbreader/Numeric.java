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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.AssertException;

/**
 * MSFT Numeric value.
 */
public class Numeric {

	private int subTypeIndex;
	private Object object;

	/**
	 * Constructor for a Numeric.
	 * @param reader the {@link PdbByteReader} from which to parse the data.
	 * @throws PdbException upon not enough data left to parse.
	 */
	public Numeric(PdbByteReader reader) throws PdbException {
		parse(reader);
	}

	public int getSubTypeIndex() {
		return subTypeIndex;
	}

	public Object getNumericObject() {
		return object;
	}

	public boolean isIntegral() {
		return (object instanceof BigInteger);
	}

	public boolean isSigned() {
		switch (subTypeIndex) {
			case 0x8000:
			case 0x8001:
			case 0x8003:
			case 0x8009:
			case 0x8017:
				return true;
			default:
				return false;
		}
	}

	public int getSize() {
		switch (subTypeIndex) {
			case 0x8000:
				return 1;
			case 0x8001:
			case 0x8002:
				return 2;
			case 0x8003:
			case 0x8004:
			case 0x8005:
				return 4;
			case 0x8006:
				return 8;
			case 0x8007:
				return 10;
			case 0x8008:
				return 16;
			case 0x8009:
			case 0x800a:
				return 8;
			case 0x800b:
				return 6;
			case 0x800c:
				return 8;
			case 0x800d:
				return 16;
			case 0x800e:
				return 20;
			case 0x800f:
				return 32;
			case 0x8017:
				return 16;
			case 0x8018:
				return 16;
			case 0x8019:
				return 16;
			case 0x801a:
				return 8;
			case 0x801b:
				return 2;
			default:
				return 0;
		}
	}

	public BigInteger getIntegral() {
		if (!(object instanceof BigInteger)) {
			throw new AssertException("Numeric is not an integral type");
		}
		return (BigInteger) object;
	}

	@Override
	public String toString() {
		return object.toString();
	}

	/**
	 * Parses an integral MSFT Numeric type from the PdbByteReader.
	 * @param reader the {@link PdbByteReader} from which to parse the data.
	 * @throws PdbException Upon not enough data left to parse or unknown subtype.
	 */
	public void parse(PdbByteReader reader) throws PdbException {
		subTypeIndex = reader.parseUnsignedShortVal();
		//TODO: create these as intrinsic types and do proper parsing?
		switch (subTypeIndex) {
			// For each case, parse bytes (to move index forward) and throw bytes away.
			//  The number of bytes parsed is based on the size of the integral type
			//  represented by subTypeIndex.
			case 0x8000: // char
				object =
					LittleEndianDataConverter.INSTANCE.getBigInteger(reader.parseBytes(1), 1, true);
				break;
			case 0x8001: // short
				object =
					LittleEndianDataConverter.INSTANCE.getBigInteger(reader.parseBytes(2), 2, true);
				break;
			case 0x8002: // unsigned short
				object = LittleEndianDataConverter.INSTANCE.getBigInteger(reader.parseBytes(2), 2,
					false);
				break;
			case 0x8003: // 32-bit
				object =
					LittleEndianDataConverter.INSTANCE.getBigInteger(reader.parseBytes(4), 4, true);
				break;
			case 0x8004: // unsigned 32-bit
				object = LittleEndianDataConverter.INSTANCE.getBigInteger(reader.parseBytes(4), 4,
					false);
				break;
			case 0x8005: // Real32
				object = ByteBuffer.wrap(reader.parseBytes(4)).getFloat();
				break;
			case 0x8006: // Real64
				object = ByteBuffer.wrap(reader.parseBytes(8)).getDouble();
				break;
			case 0x8007: // Real80
				object = new Real80(reader);
				break;
			case 0x8008: // Real128
				object = new Real128(reader);
				break;
			case 0x8009: // 64-bit
				object =
					LittleEndianDataConverter.INSTANCE.getBigInteger(reader.parseBytes(8), 8, true);
				break;
			case 0x800a: // unsigned 64-bit
				object = LittleEndianDataConverter.INSTANCE.getBigInteger(reader.parseBytes(8), 8,
					false);
				break;
			case 0x800b: // Real48
				object = new Real48(reader);
				break;
			case 0x800c: // Complex32
				object = new Complex32(reader);
				break;
			case 0x800d: // Complex64
				object = new Complex64(reader);
				break;
			case 0x800e: // Complex80
				object = new Complex80(reader);
				break;
			case 0x800f: // Complex128
				object = new Complex128(reader);
				break;

			case 0x8017: // 128-bit
				object = LittleEndianDataConverter.INSTANCE.getBigInteger(reader.parseBytes(16), 16,
					true);
				break;
			case 0x8018: // unsigned 128-bit
				object = LittleEndianDataConverter.INSTANCE.getBigInteger(reader.parseBytes(16), 16,
					false);
				break;
			case 0x8019: // DECIMAL
				object = new Decimal(reader);
				break;
			case 0x801a: // DATE
				object = new Date(reader);
				break;
			case 0x801b: // Real16
				object = new Real16(reader);
				break;

			default:
				if (subTypeIndex >= 0x8000) {
					throw new PdbException(
						String.format("Unknown Numeric subtype: 0x%04x", subTypeIndex));
				}
				object = BigInteger.valueOf(subTypeIndex);
				break;
		}
	}

//	public byte[] getBytes() {
//
//	}
	//**********************************************************************************************
	//**********************************************************************************************
	//**********************************************************************************************
	// OLD CODE FROM PdbByteWriter... TODO: evaluate to see if want to use any of it here
	//  (expect that certain parts are wrong) for outputting bytes of a Numeric.  There were
	//  problems in the parseNumeric() code that was in the PdbByteReader.
	// Note: as of this writing, the following code is still in the PdbByteWriter as it is
	//  used by TypesTest methods.  TODO: if we get a suitable replacement here, then delete
	//  method in PdbByteWriter and convert the tests to use this class.
//	/**
//	 * Put the data to occupy the next Numeric field in the byte array.  For Numeric definition,
//	 *  see the PdbByteReader method for reading such a field.  If value is too large for the
//	 *  encoding code, the value is masked.
//	 * @param value The BigInteger containing the value to be written into the Numeric field.
//	 * @param code The encoding code for representing the Numeric field
//	 */
//	public void putNumeric(BigInteger value, int code) {
//		// Drop bits. Letting value become signed too.
//		BigInteger arg = value.and(new BigInteger("ffffffffffffffff", 16));
//		long longValue;
//		try {
//			longValue = value.longValueExact();
//		}
//		catch (ArithmeticException e) {
//			// Should not happen since we "ANDed" the value.  Fail silently
//			return;
//		}
//		switch (code) {
//			// For each case, parse bytes (to move index forward) and throw bytes away.
//			//  The number of bytes parsed is based on the size of the integral type
//			//  represented by subTypeIndex.
//			case 0x8000: // char
//				putUnsignedShort(code);
//				putUnsignedByte((int) (longValue & 0xff));
//				break;
//			case 0x8001: // short
//				putUnsignedShort(code);
//				putShort((short) (longValue & 0xffff));
//				break;
//			case 0x8002: // unsigned short
//				putUnsignedShort(code);
//				putUnsignedShort((int) (longValue & 0xffff));
//				break;
//			case 0x8003: // 32-bit
//				putUnsignedShort(code);
//				putInt((int) (longValue & 0xffffffff));
//				break;
//			case 0x8004: // unsigned 32-bit
//				putUnsignedShort(code);
//				putUnsignedInt(longValue & 0xffffffff);
//				break;
//			case 0x8009: // 64-bit
//				putUnsignedShort(code);
//				putLong(longValue);
//				break;
//			case 0x800a: // unsigned 64-bit
//				putUnsignedShort(code);
//				putUnsignedLong(arg);
//				break;
//			default:
//				return; // Fail silently.
//		}
//	}

	//**********************************************************************************************
	//**********************************************************************************************
	//**********************************************************************************************
	/*
	 * Below can considered to be temporary classes to contain information pertaining to their
	 * type.
	 */
	private abstract class AbstractNumericOther {
		private byte[] bytes;

		AbstractNumericOther(PdbByteReader reader, int num) throws PdbException {
			parse(reader, num);
		}

		private void parse(PdbByteReader reader, int num) throws PdbException {
			bytes = reader.parseBytes(num);
		}

		private byte[] getBytes() {
			return bytes;
		}
	}

	/**
	 * Represents a Real16 number
	 */
	private class Real16 extends AbstractNumericOther {
		private Real16(PdbByteReader reader) throws PdbException {
			super(reader, 2);
		}
	}

	/**
	 * Represents a Real48 number
	 */
	private class Real48 extends AbstractNumericOther {
		private Real48(PdbByteReader reader) throws PdbException {
			super(reader, 6);
		}
	}

	/**
	 * Represents a Real80 number
	 */
	private class Real80 extends AbstractNumericOther {
		private Real80(PdbByteReader reader) throws PdbException {
			super(reader, 10);
		}
	}

	/**
	 * Represents a Real128 number
	 */
	private class Real128 extends AbstractNumericOther {
		private Real128(PdbByteReader reader) throws PdbException {
			super(reader, 16);
		}
	}

	/**
	 * Represents a Complex32 (2 x 32-bits)
	 */
	private class Complex32 extends AbstractNumericOther {
		private Complex32(PdbByteReader reader) throws PdbException {
			super(reader, 8);
		}
	}

	/**
	 * Represents a Complex64 (2 x 64-bits)
	 */
	private class Complex64 extends AbstractNumericOther {
		private Complex64(PdbByteReader reader) throws PdbException {
			super(reader, 16);
		}
	}

	/**
	 * Represents a Complex80 (2 x 80-bits)
	 */
	private class Complex80 extends AbstractNumericOther {
		private Complex80(PdbByteReader reader) throws PdbException {
			super(reader, 20);
		}
	}

	/**
	 * Represents a Complex128 (2 x 128-bits)
	 */
	private class Complex128 extends AbstractNumericOther {
		private Complex128(PdbByteReader reader) throws PdbException {
			super(reader, 32);
		}
	}

	/**
	 * Represents a MSFT DATE.
	 */
	private class Date extends AbstractNumericOther {
		// Is said to be represented by a double.
		Date(PdbByteReader reader) throws PdbException {
			super(reader, 8);
		}
	}

	/**
	 * Represents a MSFT DECIMAL.
	 */
	private class Decimal extends AbstractNumericOther {
		/*
		 *  Supposed to be:
		 *   WORD reserved
		 *   BYTE scale
		 *   BYTE sign
		 *   ULONG Hi32
		 *   ULONGLONG Lo64
		 */
		Decimal(PdbByteReader reader) throws PdbException {
			super(reader, 16);
		}
	}

}
