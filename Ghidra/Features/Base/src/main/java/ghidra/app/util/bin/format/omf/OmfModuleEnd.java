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

public class OmfModuleEnd extends OmfRecord {
	//private byte moduleType;
	//private OmfFixupRecord.FixupTarget startAddress;

	public OmfModuleEnd(BinaryReader reader) throws IOException {
		readRecordHeader(reader);
		/* The record type is not handled so simply skip the information 
		moduleType = reader.readNextByte();
		if (hasStartAddress()) {
			endData = reader.readNextByte();
			frameDatum = readInt1Or2(reader, hasBigFields());
			targetDatum = readInt1Or2(reader, hasBigFields());
			targetDisplacement readInt2Or4(reader, hasBigFields());
		}
		readCheckSumByte(reader);
		*/
		reader.setPointerIndex(reader.getPointerIndex() + getRecordLength());
	}
/*
	public boolean isMainProgramModule() {
		return ((moduleType & 0x80) != 0);
	}

	public boolean hasStartAddress() {
		return ((moduleType & 0x40) != 0);
	}
*/
}
