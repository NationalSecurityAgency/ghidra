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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;

/**
 * Utility class for OMF-based file formats
 */
public class OmfUtils {

	/** Data type category */
	public static final String CATEGORY_PATH = "/OMF";

	public static Omf2or4 readInt2Or4(BinaryReader reader, boolean isBig) throws IOException {
		return isBig ? new Omf2or4(4, reader.readNextInt())
				: new Omf2or4(2, reader.readNextUnsignedShort());
	}

	public static OmfIndex readIndex(BinaryReader reader) throws IOException {
		int length;
		int indexWord;
		byte firstByte = reader.readNextByte();
		if ((firstByte & 0x80) != 0) {
			indexWord = (firstByte & 0x7f) * 0x100 + (reader.readNextByte() & 0xff);
			length = 2;
		}
		else {
			indexWord = firstByte;
			length = 1;
		}
		return new OmfIndex(length, indexWord);
	}

	/**
	 * Read the OMF string format: 1-byte length, followed by that many ascii characters
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the string
	 * @return the read OMF string
	 * @throws IOException if an IO-related error occurred
	 */
	public static OmfString readString(BinaryReader reader) throws IOException {
		int count = reader.readNextUnsignedByte();
		return new OmfString(count, reader.readNextAsciiString(count));
	}

	/**
	 * Gets the name of the given record type
	 * 
	 * @param type The record type
	 * @param recordTypesClass The class that contains accessible OMF type fields
	 * @return The name of the given record type
	 */
	public final static String getRecordName(int type, Class<?> recordTypesClass) {
		for (Field field : recordTypesClass.getDeclaredFields()) {
			int modifiers = field.getModifiers();
			if (Modifier.isFinal(modifiers) && Modifier.isStatic(modifiers)) {
				try {
					Integer value = (Integer) field.get(null);
					if (type == value) {
						return field.getName();
					}
				}
				catch (Exception e) {
					break;
				}
			}
		}
		return "<UNKNOWN>";
	}

	/**
	 * Converts the given {@link OmfRecord} to a generic OMF record {@link DataType}
	 * 
	 * @param record The OMF record to convert
	 * @param name The name of the OMF record
	 * @return A {@link DataType} for the given OMF record
	 */
	public static DataType toOmfRecordDataType(OmfRecord record, String name) {
		StructureDataType struct = new StructureDataType(name, 0);
		struct.add(ByteDataType.dataType, "type", null);
		struct.add(WordDataType.dataType, "length", null);
		struct.add(new ArrayDataType(ByteDataType.dataType, record.getRecordLength() - 1, 1),
			"contents", null);
		struct.add(ByteDataType.dataType, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}

	/**
	 * Reads all the {@link OmfRecord records} associated with the given 
	 * {@link AbstractOmfRecordFactory}
	 * 
	 * @param factory The {@link AbstractOmfRecordFactory}
	 * @return A {@link List} of read {@link OmfRecord records}
	 * @throws IOException if there was an IO-related error
	 * @throws OmfException if there was a problem with the OMF specification
	 */
	public static List<OmfRecord> readRecords(AbstractOmfRecordFactory factory)
			throws OmfException, IOException {
		List<OmfRecord> records = new ArrayList<>();
		factory.reset();

		while (true) {
			OmfRecord rec = factory.readNextRecord();
			records.add(rec);
			if (rec.getRecordType() == factory.getEndRecordType()) {
				break;
			}
		}
		
		return records;
	}
}
