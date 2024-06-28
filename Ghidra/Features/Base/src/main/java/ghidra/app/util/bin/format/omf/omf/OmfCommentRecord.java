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
package ghidra.app.util.bin.format.omf.omf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class OmfCommentRecord extends OmfRecord {
	// Language translator comment
	public static final byte COMMENT_CLASS_TRANSLATOR = 0;
	// Record specifying name of object
	public static final byte COMMENT_CLASS_LIBMOD = (byte) 0xA3;
	// Default library cmd
	public static final byte COMMENT_CLASS_DEFAULT_LIBRARY = (byte) 0x9F;
	// Watcom compile parameters
	public static final byte COMMENT_CLASS_WATCOM_SETTINGS = (byte) 0x9b;
	// Microsoft compile parameters
	public static final byte COMMENT_CLASS_MICROSOFT_SETTINGS = (byte) 0x9d;

	private byte commentType;
	private byte commentClass;
	private OmfString value;

	public OmfCommentRecord(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public void parseData() throws IOException, OmfException {
		commentType = dataReader.readNextByte();
		commentClass = dataReader.readNextByte();

		switch (commentClass) {
			case COMMENT_CLASS_TRANSLATOR:
			case COMMENT_CLASS_DEFAULT_LIBRARY:
				byte[] bytes = dataReader.readNextByteArray(getRecordLength() -
					3 /* 3 = sizeof(commentType+commentClass+trailing_crcbyte*/);
				value = new OmfString(bytes.length, new String(bytes, StandardCharsets.US_ASCII)); // assuming ASCII
				break;
			case COMMENT_CLASS_LIBMOD:
				value = OmfUtils.readString(dataReader);
				break;
			default:
				break;
		}
	}

	public byte getCommentType() {
		return commentType;
	}

	public byte getCommentClass() {
		return commentClass;
	}

	public String getValue() {
		return value.str();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		int strlen = getRecordLength() - 3;

		StructureDataType struct = new StructureDataType(OmfRecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", "");
		struct.add(BYTE, "comment_type", null);
		struct.add(BYTE, "comment_class", null);
		if (strlen > 0) {
			struct.add(new StringDataType(), strlen, "str", null);
		}
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}
}
