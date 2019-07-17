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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The CONSTANT_Integer_info structures represent 4-byte numeric (int) constants:
 * <pre>
 * 		CONSTANT_Integer_info {
 * 			u1 tag;
 * 			u4 bytes;
 * 		}
 * </pre>
 */
public class ConstantPoolIntegerInfo extends AbstractConstantPoolInfoJava {

	private int bytes;

	public ConstantPoolIntegerInfo( BinaryReader reader ) throws IOException {
		super( reader );
		bytes = reader.readNextInt();
	}

	/**
	 * The bytes item of the CONSTANT_Integer_info structure represents the value
	 * of the int constant. The bytes of the value are stored in big-endian (high byte
	 * first) order.
	 * @return the value of the integer constant
	 */
	public int getValue() {
		return bytes;
	}

	@Override
	public String toString() {
		return "" + getValue();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_Integer_info";
		Structure structure = new StructureDataType( name, 0 );
		structure.add(  BYTE,   "tag", null );
		structure.add( DWORD, "bytes", null );
		return structure;
	}

}
