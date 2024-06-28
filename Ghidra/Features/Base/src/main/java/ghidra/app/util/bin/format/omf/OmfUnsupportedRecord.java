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

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * A known but currently unsupported OMF record
 */
public class OmfUnsupportedRecord extends OmfRecord {

	private Class<?> recordTypesClass;

	/**
	 * Create a new {@link OmfUnsupportedRecord}
	 *  
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @param recordTypesClass The class that contains accessible OMF type fields
	 * @throws IOException If an IO-related error occurred
	 */
	public OmfUnsupportedRecord(BinaryReader reader, Class<?> recordTypesClass) throws IOException {
		super(reader);
		this.recordTypesClass = recordTypesClass;
	}

	@Override
	public void parseData() throws IOException, OmfException {
		// No record-specific data to read
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return OmfUtils.toOmfRecordDataType(this,
			OmfUtils.getRecordName(recordType, recordTypesClass));
	}
}
