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
 * The CONSTANT_Double_info represent 8-byte numeric (double) constants:
 * <pre>
 * 		CONSTANT_Double_info {
 * 			u1 tag;
 * 			u4 high_bytes;
 * 			u4 low_bytes;
 * 		}
 * </pre>
 * All 8-byte constants take up two entries in the constant_pool table of the class
 * file. If a CONSTANT_Double_info structure is the item
 * in the constant_pool table at index n, then the next usable item in the pool is
 * located at index n+2. The constant_pool index n+1 must be valid but is considered
 * unusable.
 * <p>
 * In retrospect, making 8-byte constants take two constant pool entries was a poor choice.
 */
public class ConstantPoolDoubleInfo extends AbstractConstantPoolInfoJava {

	private int highBytes;
	private int lowBytes;

	public ConstantPoolDoubleInfo( BinaryReader reader ) throws IOException {
		super( reader );
		highBytes = reader.readNextInt();
		lowBytes = reader.readNextInt();
	}

	/**
	 * The value represented by the CONSTANT_Double_info structure is determined
	 * as follows. The high_bytes and low_bytes items are converted into the long
	 * constant bits, which is equal to
	 * 		((long) high_bytes << 32) + low_bytes
	 * Then:
	 * 		If bits is 0x7ff0000000000000L, the double value will be positive infinity.
	 * 
	 * 		If bits is 0xfff0000000000000L, the double value will be negative infinity.
	 * 
	 * 		If bits is in the range 0x7ff0000000000001L through 0x7fffffffffffffffL
	 * 		or in the range 0xfff0000000000001L through 0xffffffffffffffffL, the
	 * 		double value will be NaN.
	 * 
	 * 		In all other cases, let s, e, and m be three values that might be computed from bits:
	 * 
	 * 			int s = ((bits >> 63) == 0) ? 1 : -1;
	 * 			int e = (int)((bits >> 52) & 0x7ffL);
	 * 			long m = (e == 0) ?
	 * 						(bits & 0xfffffffffffffL) << 1 :
	 * 						(bits & 0xfffffffffffffL) | 0x10000000000000L;
	 * 
	 * Then the floating-point value equals the double value of the mathematical
	 * expression s ? m ? 2e-1075.
	 * @return the double value
	 */
	public double getValue() {
		return Double.longBitsToDouble( ( ( (long)highBytes ) << 32 ) + ( lowBytes & 0xffffffffL ) );
	}

	public long getRawBytes() {
		return (((long)highBytes) << 32 ) + (lowBytes & 0xffffffffL);
	}

	@Override
	public String toString() {
		return "" + getValue();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_Long_info";
		Structure structure = new StructureDataType( name, 0 );
		structure.add( BYTE,  "tag", null );
		structure.add( DWORD, "high_bytes", null );
		structure.add( DWORD, "low_bytes", null );
		return structure;
	}

}
