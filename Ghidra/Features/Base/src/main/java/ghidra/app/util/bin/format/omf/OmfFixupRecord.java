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
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;

public class OmfFixupRecord extends OmfRecord {

	private Subrecord[] subrecs;
	private OmfEnumeratedData lastLEData = null;
	private OmfIteratedData lastLIData = null;
	
	public OmfFixupRecord(BinaryReader reader) throws IOException {
		ArrayList<Subrecord> subreclist = new ArrayList<Subrecord>();
		boolean hasBigFields = ((getRecordType() & 1)!=0);
		
		readRecordHeader(reader);
		long max = reader.getPointerIndex() + getRecordLength() - 1;
		while(reader.getPointerIndex() < max) {
			byte peek = reader.peekNextByte();
			if ((peek & 0x80)==0) {
				ThreadSubrecord subrec = ThreadSubrecord.readThreadSubrecord(reader, hasBigFields);
				subreclist.add(subrec);
			}
			else {
				FixupSubrecord subrec = FixupSubrecord.readFixupSubrecord(reader, hasBigFields);
				subreclist.add(subrec);
			}
		}
		subrecs = new Subrecord[subreclist.size()];
		subreclist.toArray(subrecs);
		readCheckSumByte(reader);
	}
	
	public void setDataBlock(Object last) {
		if (last instanceof OmfEnumeratedData) {
			lastLEData = (OmfEnumeratedData)last;
			lastLIData = null;
		}
		else {
			lastLIData = (OmfIteratedData)last;
			lastLEData = null;
		}
	}
	
	public Subrecord[] getSubrecords() {
		return subrecs;
	}

	public static class FixupState {
		public Language language;
		OmfFileHeader header;
		public ThreadSubrecord[] frameThreads = new ThreadSubrecord[4];
		public ThreadSubrecord[] targetThreads = new ThreadSubrecord[4];
		public OmfFixupRecord currentFixupRecord;
		public ArrayList<OmfGroupRecord> groups;
		public ArrayList<OmfSymbol> externals;
		public int frameState;			// Frame of item being referred to
		public long targetState;		// Address of item being referred to
		public Address locAddress;		// Location of data to be patched
		public boolean M;				// true for segment-relative, false for self-relative
		public int locationType;
		
		public FixupState(OmfFileHeader header,ArrayList<OmfSymbol> externsyms,Language lang) {
			for(int i=0;i<4;++i) {
				frameThreads[i] = null;
				targetThreads[i] = null;
			}
			this.header = header;
			groups = header.getGroups();
			externals = externsyms;
			language = lang;
		}
		
		public void clear() {
			targetState = -1;
			locAddress = null;
			locationType = -1;
		}
	}
	
	public static class Subrecord {
		private boolean isThread;
		
		public Subrecord(boolean isthread) {
			isThread = isthread;
		}
		
		public boolean isThread() {
			return isThread;
		}
	}
	
	public static class ThreadSubrecord extends Subrecord {
		private byte type;
		private int index;

		public ThreadSubrecord() {
			super(true);
		}
		
		public int getMethod() {
			return (type>>2) & 7;
		}
		
		public int getIndex() {
			return index;
		}
		
		public boolean isFrameThread() {
			return ((type>>6)&1)!=0;
		}
		
		public int getThreadNum() {
			return (type & 3);
		}

		public void updateState(FixupState state) {
			if (isFrameThread())
				state.frameThreads[getThreadNum()] = this;
			else
				state.targetThreads[getThreadNum()] = this;
		}
		
		public static ThreadSubrecord readThreadSubrecord(BinaryReader reader,boolean hasBigFields) throws IOException {
			ThreadSubrecord thread = new ThreadSubrecord();
			thread.type = reader.readNextByte();
			int method = thread.getMethod();
			if (method < 4)
				thread.index = OmfRecord.readInt1Or2(reader, hasBigFields);
			else
				thread.index = -1;
			return thread;
		}
	}
	
	public static class FixupTarget {
		private byte fixData;
		private int frameDatum;
		private int targetDatum;
		private int targetDisplacement;

		public boolean isFrameThread() {
			return ((fixData>>7)&1)!=0;
		}
		
		public boolean isTargetThread() {
			return ((fixData>>3)&1)!=0;
		}
		
		public int getFrameMethod() {
			return ((fixData>>4)&7);
		}
		
		public int getP() {
			int res = (fixData >>2)&1;
			return res;
		}
		
		public void resolveFrame(FixupState state) throws OmfException {
			int method;
			int index;
			if (isFrameThread()) {
				// Frame datum from a thread
				int threadnum = ((fixData>>4)&3);
				ThreadSubrecord subrec = state.frameThreads[threadnum];
				method = subrec.getMethod();
				index = subrec.getIndex();
			}
			else {
				method = getFrameMethod();
				index = frameDatum;
			}
			switch(method) {
			case 0:				// Index is for a segment
				state.frameState = state.header.resolveSegment(index).getFrameDatum();
				break;
			case 1:				// Index is for a group
				state.frameState = state.groups.get(index-1).getFrameDatum();
				break;
			case 2:				// Index is for an external symbol
				state.frameState = state.externals.get(index-1).getFrameDatum();
				break;
			case 4:				// Segment Index grabbed from datablock
				if (state.currentFixupRecord.lastLEData != null)
					index = state.currentFixupRecord.lastLEData.getSegmentIndex();
				else
					index = state.currentFixupRecord.lastLIData.getSegmentIndex();
				state.frameState = state.header.resolveSegment(index).getFrameDatum();
				break;
			case 5:				// Frame determined by target
				// TODO:  Fill this in properly
				break;
			default:
				state.frameState = -1;			// Indicate an error condition
			}
		}
		
		public void resolveTarget(FixupState state) throws OmfException {
			int method;
			int index;
			if (isTargetThread()) {
				int threadnum = fixData & 3;
				ThreadSubrecord subrec = state.targetThreads[threadnum];
				method = getP();		// Most significant bit is frame fixup subrecord
				method <<= 2;
				method |= subrec.getMethod();	// Least significant 2 bits are from the thread
				index = subrec.getIndex();
			}
			else {
				method = fixData & 7;
				index = targetDatum;
			}

			switch(method) {
			case 0:			// Index is for a segment
				state.targetState = state.header.resolveSegment(index).getStartAddress();
				state.targetState += targetDisplacement;
				break;
			case 1:			// Index is for a group
				state.targetState = state.groups.get(index-1).getStartAddress();
				state.targetState += targetDisplacement;
				break;
			case 2:			// Index is for an external symbol
				state.targetState = state.externals.get(index-1).getAddress().getOffset();
				state.targetState += targetDisplacement;
				break;
		//	case 3:			// Not supported by many linkers
			case 4:			// segment only, no displacement
				state.targetState = state.header.resolveSegment(index).getStartAddress();
				break;
			case 5:			// group only, no displacement
				state.targetState = state.groups.get(index-1).getStartAddress();
				break;
			case 6:			// external only, no displacement
				state.targetState = state.externals.get(index-1).getAddress().getOffset();
				break;
			default:
				state.targetState = -1;			// This indicates an unresolved target
			}
		}
		
		public static FixupTarget readFixupTarget(BinaryReader reader,boolean hasBigFields) throws IOException {
			FixupTarget fixupTarget = new FixupTarget();
			fixupTarget.fixData = reader.readNextByte();
			if ((fixupTarget.fixData & 0x80)==0) {		// F=0  (explicit frame method (and datum))
				int method = (fixupTarget.fixData >> 4)&7;
				if (method <3) {
					fixupTarget.frameDatum = OmfRecord.readIndex(reader);
				}
			}
			if ((fixupTarget.fixData & 0x08)==0) {		// T=0  (explicit target)
				fixupTarget.targetDatum = OmfRecord.readIndex(reader);
			}
			if ((fixupTarget.fixData & 0x04)==0)		// P=0
				fixupTarget.targetDisplacement = OmfRecord.readInt2Or4(reader, hasBigFields);
			return fixupTarget;
		}
	}
	
	public static class FixupSubrecord extends Subrecord {
		private byte lobyte;			// lo-byte of location
		private byte hibyte;			// hi-byte of location
		private FixupTarget target;
		
		public FixupSubrecord() {
			super(false);
		}
		
		public void resolveFixup(FixupState state) throws OmfException {
			
			target.resolveTarget(state);		// Resolve target first as frame may need to reference results
			target.resolveFrame(state);
			state.M = ((lobyte>>6)&1)!=0;
			state.locationType = ((lobyte>>2)&0xf);
			int dataRecordOffset = lobyte & 3;
			dataRecordOffset <<= 8;
			dataRecordOffset |= (hibyte) & 0xff;
			long blockDisplace;
			int segIndex;
			if (state.currentFixupRecord.lastLEData != null) {
				blockDisplace = state.currentFixupRecord.lastLEData.getDataOffset();
				segIndex = state.currentFixupRecord.lastLEData.getSegmentIndex();
			}
			else {
				blockDisplace = state.currentFixupRecord.lastLIData.getDataOffset();
				segIndex = state.currentFixupRecord.lastLIData.getSegmentIndex();
			}
			OmfSegmentHeader seg = state.header.resolveSegment(segIndex);
			state.locAddress = seg.getAddress(state.language).add(blockDisplace + dataRecordOffset);			
		}
		
		public static FixupSubrecord readFixupSubrecord(BinaryReader reader,boolean hasBigFields) throws IOException {
			FixupSubrecord fixupSubrecord = new FixupSubrecord();
			fixupSubrecord.lobyte = reader.readNextByte();
			fixupSubrecord.hibyte = reader.readNextByte();
			fixupSubrecord.target = FixupTarget.readFixupTarget(reader, hasBigFields);
			return fixupSubrecord;
		}		
	}
}
