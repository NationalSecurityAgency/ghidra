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
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

public class OmfLineNumberRecord extends OmfRecord {
	private int baseGroup;
	private int baseSegment;
	private LineSubrecord[] linenumber;
	
	public OmfLineNumberRecord(BinaryReader reader) throws IOException {
		readRecordHeader(reader);
		boolean hasBigFields = hasBigFields();
		baseGroup = OmfRecord.readIndex(reader);
		baseSegment = OmfRecord.readIndex(reader);
		long max = reader.getPointerIndex() + getRecordLength() - 1;
		ArrayList<LineSubrecord> linelist = new ArrayList<LineSubrecord>();
		while(reader.getPointerIndex() < max) {
			LineSubrecord subrec = LineSubrecord.read(reader,hasBigFields);
			linelist.add(subrec);
		}
		readCheckSumByte(reader);
		linenumber = new LineSubrecord[linelist.size()];
		linelist.toArray(linenumber);
	}
	
	public static class LineSubrecord {
		private int lineNumber;
		private int lineNumberOffset;
		
		public static LineSubrecord read(BinaryReader reader,boolean hasBigFields) throws IOException {
			LineSubrecord subrec = new LineSubrecord();
			subrec.lineNumber = reader.readNextShort() & 0xffff;
			subrec.lineNumberOffset = OmfRecord.readInt2Or4(reader, hasBigFields);
			return subrec;
		}
	}
}
