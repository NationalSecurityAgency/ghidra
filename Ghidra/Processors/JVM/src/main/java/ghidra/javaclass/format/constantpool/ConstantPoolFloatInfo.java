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
package ghidra.javaclass.format.constantpool;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The CONSTANT_Float_info structures represent 4-byte numeric (float) constants:
 * <pre>
 * 		CONSTANT_Float_info {
 * 			u1 tag;
 * 			u4 bytes;
 * 		}
 * </pre>
 */
public class ConstantPoolFloatInfo extends AbstractConstantPoolInfoJava {

	private int bytes;

	public ConstantPoolFloatInfo( BinaryReader reader ) throws IOException {
		super( reader );
		bytes = reader.readNextInt();
	}

	/**
	 * The bytes item of the CONSTANT_Float_info structure represents the value
	 * of the float constant in IEEE 754 floating-point single format (?2.3.2). The
	 * bytes of the single format representation are stored in big-endian (high byte
	 * first) order.
	 * 
	 * The value represented by the CONSTANT_Float_info structure is determined
	 * as follows. The bytes of the value are first converted into an int constant bits.
	 * Then:
	 * 		If bits is 0x7f800000, the float value will be positive infinity.
	 * 
	 * 		If bits is 0xff800000, the float value will be negative infinity.
	 * 
	 * 		If bits is in the range 0x7f800001 through 0x7fffffff or in the range
	 * 		0xff800001 through 0xffffffff, the float value will be NaN.
	 * 
	 * 		In all other cases, let s, e, and m be three values that might be computed from
	 * 		bits:
	 * 			int s = ((bits >> 31) == 0) ? 1 : -1;
	 * 			int e = ((bits >> 23) & 0xff);
	 * 			int m = (e == 0) ?
	 * 						(bits & 0x7fffff) << 1 :
	 * 						(bits & 0x7fffff) | 0x800000;
	 * Then the float value equals the result of the mathematical expression 
	 * 		s x m x 2e-150.
	 * 
	 * @return the value of the float constant
	 */
	
	public int getRawBytes() {
		return bytes;
	}

	public float getValue() {
		return Float.intBitsToFloat( bytes );
	}

	@Override
	public String toString() {
		return "" + getValue();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_Float_info";
		Structure structure = new StructureDataType( name, 0 );
		structure.add(  BYTE,   "tag", null );
		structure.add( DWORD, "bytes", null );
		return structure;
	}

}
