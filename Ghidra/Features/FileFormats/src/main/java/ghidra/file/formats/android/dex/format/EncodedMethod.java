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
package ghidra.file.formats.android.dex.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class EncodedMethod implements StructConverter {

	private long _fileOffset;
	private int _methodIndex;

	private int methodIndexDifference;
	private int accessFlags;
	private int codeOffset;

	private int methodIndexDifferenceLength;// in bytes
	private int accessFlagsLength;// in bytes
	private int codeOffsetLength;// in bytes

	private CodeItem codeItem;

	public EncodedMethod( BinaryReader reader ) throws IOException {

		LEB128 leb128 = LEB128.readUnsignedValue(reader);
		_fileOffset = leb128.getOffset();
		methodIndexDifference = leb128.asUInt32();
		methodIndexDifferenceLength = leb128.getLength();

		leb128 = LEB128.readUnsignedValue(reader);
		accessFlags = leb128.asUInt32();
		accessFlagsLength = leb128.getLength();

		leb128 = LEB128.readUnsignedValue(reader);
		codeOffset = leb128.asUInt32();
		codeOffsetLength = leb128.getLength();

		if ( codeOffset > 0 ) {
			codeItem = new CodeItem( reader.clone(codeOffset) );
		}
	}

	public long getFileOffset( ) {
		return _fileOffset;
	}

	void setMethodIndex( int methodIndex ) {
		_methodIndex = methodIndex;
	}

	public int getMethodIndex( ) {
		return _methodIndex;
	}

	public int getMethodIndexDifference( ) {
		return methodIndexDifference;
	}

	public int getAccessFlags( ) {
		return accessFlags;
	}

	public boolean isStatic( ) {
		return ( accessFlags & AccessFlags.ACC_STATIC ) != 0;
	}

	public int getCodeOffset( ) {
		return codeOffset;
	}

	public CodeItem getCodeItem( ) {
		return codeItem;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		String name = "encoded_method_" + methodIndexDifferenceLength + "_" + accessFlagsLength + "_" + codeOffsetLength;
		Structure structure = new StructureDataType( name, 0 );
		structure.add( new ArrayDataType( BYTE, methodIndexDifferenceLength, BYTE.getLength( ) ), "method_idx_diff", null );
		structure.add( new ArrayDataType( BYTE, accessFlagsLength, BYTE.getLength( ) ), "access_flags", null );
		structure.add( new ArrayDataType( BYTE, codeOffsetLength, BYTE.getLength( ) ), "code_off", null );
		structure.setCategoryPath( new CategoryPath( "/dex/encoded_method" ) );
		return structure;
	}
}
