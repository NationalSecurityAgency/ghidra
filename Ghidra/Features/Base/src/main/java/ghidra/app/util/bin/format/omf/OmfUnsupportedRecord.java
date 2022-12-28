/* ###
 * IP: GHIDRA
 * REVIEWED: NO
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

public class OmfUnsupportedRecord extends OmfRecord {
	private long offset;
	private boolean logMessage;

	/***
	 * Skip an unsupported OMF record.
	 *  
	 * @param reader The byte stream with the unsupported record to skip
	 * @throws IOException
	 */
	public OmfUnsupportedRecord(BinaryReader reader, boolean log) throws IOException {
		readRecordHeader(reader);
		offset = reader.getPointerIndex();
		logMessage = log;

		reader.setPointerIndex(reader.getPointerIndex() + getRecordLength());
	}

	public boolean doLogMessage() {
		return logMessage;
	}

	/***
	 * Get a message suitable for logging about this record
	 * @return String Message text about record
	 */
	public String getMessage() {
		return "Unsupported OMF record of type " + Long.toHexString((getRecordType() & 0xff)) + " of length " + getRecordLength() + " at " + offset;
	}

}