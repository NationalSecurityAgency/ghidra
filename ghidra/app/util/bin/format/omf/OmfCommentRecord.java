/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

public class OmfCommentRecord extends OmfRecord {
	private byte commentType;
	private byte commentClass;
	private String value;
	
	public OmfCommentRecord(BinaryReader reader) throws IOException {
		readRecordHeader(reader);
		commentType = reader.readNextByte();
		commentClass = reader.readNextByte();
		byte[] bytes = reader.readNextByteArray(getRecordLength()-3);		// May not be a string, depending on commentClass
		if ((commentClass == (byte)0)||(commentClass == (byte)0xA3)) {
			int len = bytes[0] & 0xff;
			value = new String(bytes,1,len);		// This is the translator/libmod string
		}
	//	value = reader.readNextAsciiString(getRecordLength() - 3);
		readCheckSumByte(reader);
	}
	
	public byte getCommentClass() {
		return commentClass;
	}
	
	public String getValue() {
		return value;
	}
}
