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
 * The CONSTANT_Long_info represent 8-byte numeric (long) constants:
 * <pre>
 * 		CONSTANT_Long_info {
 * 			u1 tag;
 * 			u4 high_bytes;
 * 			u4 low_bytes;
 * 		}
 * </pre>
 * All 8-byte constants take up two entries in the constant_pool table of the class
 * file. If a CONSTANT_Long_info structure is the item
 * in the constant_pool table at index n, then the next usable item in the pool is
 * located at index n+2. The constant_pool index n+1 must be valid but is considered
 * unusable.
 * <p>
 * In retrospect, making 8-byte constants take two constant pool entries was a poor choice.
 */
public class ConstantPoolLongInfo extends AbstractConstantPoolInfoJava {

	private int highBytes;
	private int lowBytes;

	public ConstantPoolLongInfo( BinaryReader reader ) throws IOException {
		super( reader );
		highBytes = reader.readNextInt();
		lowBytes = reader.readNextInt();
	}

	/**
	 * The unsigned high_bytes and low_bytes items of the CONSTANT_Long_info
	 * structure together represent the value of the long constant
	 * <pre>
	 * 		((long) high_bytes << 32) + low_bytes
	 * </pre>
	 * where the bytes of each of high_bytes and low_bytes are stored in big-endian
	 * (high byte first) order.
	 * @return the long value
	 */
	public long getValue() {
		return ( ( (long)highBytes ) << 32 ) + ( lowBytes & 0xffffffffL );
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
