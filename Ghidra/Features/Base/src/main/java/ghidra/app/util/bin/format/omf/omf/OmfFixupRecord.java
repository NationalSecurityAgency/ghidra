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
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class OmfFixupRecord extends OmfRecord {
	private Subrecord[] subrecs;
	private OmfData lastData = null;

	/**
	 * Read a Fixup record from the input reader
	 * @param reader The actual reader
	 * @throws IOException if there was an IO-related error
	 */
	public OmfFixupRecord(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public void parseData() throws IOException, OmfException {
		ArrayList<Subrecord> subreclist = new ArrayList<>();
		long max = dataReader.getPointerIndex() + getRecordLength() - 1;
		while (dataReader.getPointerIndex() < max) {
			subreclist.add(Subrecord.readSubrecord(dataReader, hasBigFields()));
		}
		subrecs = new Subrecord[subreclist.size()];
		subreclist.toArray(subrecs);
	}

	/**
	 * @param last The Datablock this fixup record is meant for
	 */
	public void setDataBlock(OmfData last) {
		lastData = last;
	}

	/**
	 * @return The datablock this fixup record is meant for
	 */
	public OmfData getDataBlock() {
		return lastData;
	}

	/**
	 * @return The array of subrecords
	 */
	public Subrecord[] getSubrecords() {
		return subrecs;
	}

	@SuppressWarnings("unused")
	public static class Subrecord {
		private byte first;
		private byte hiFixup;
		private byte fixData;
		private OmfIndex index;
		private OmfIndex frameDatum;
		private OmfIndex targetDatum;
		private Omf2or4 targetDisplacement;

		/**
		 * Read the next subrecord from the input reader
		 *
		 * @param reader The input file
		 * @param hasBigFields Is this 16 or 32 bit values
		 * @return The read subrecord
		 * @throws IOException if there was an IO-related error
		 */
		public static Subrecord readSubrecord(BinaryReader reader, boolean hasBigFields)
				throws IOException {
			int method;
			final var rec = new Subrecord();
			rec.first = reader.readNextByte();
			rec.index = new OmfIndex(1, -1);
			if (rec.isThreadSubrecord()) {
				method = rec.getThreadMethod();
				if (method < 4) {
					rec.index = OmfUtils.readIndex(reader);
				}
				return rec;
			}
			rec.targetDisplacement = new Omf2or4(2, 0);
			rec.targetDatum = new OmfIndex(1, 0);
			rec.hiFixup = reader.readNextByte();
			rec.fixData = reader.readNextByte();
			method = rec.getFrameMethod();
			if (!rec.isFrameThread() && method < 3) { // F=0  (explicit frame method (and datum))
				rec.frameDatum = OmfUtils.readIndex(reader);
			}
			if (!rec.isTargetThread()) { // T=0  (explicit target)
				rec.targetDatum = OmfUtils.readIndex(reader);
			}
			if ((rec.fixData & 0x04) == 0) { // P=0
				rec.targetDisplacement = OmfUtils.readInt2Or4(reader, hasBigFields);
			}
			return rec;
		}

		/**
		 * @return True if this is a Thread subrecord type
		 */
		public boolean isThreadSubrecord() {
			return (first & 0x80) == 0;
		}

		/**
		 * @return The method value from a Thread subrecord
		 */
		public int getThreadMethod() {
			return first >> 2 & 7;
		}

		/**
		 * @return True if this is a frame reference
		 */
		public boolean isFrameInSubThread() {
			return (first & 0x40) != 0;
		}

		/**
		 * @return Get the index for explicit thread or frame
		 */
		public int getIndex() {
			return index.value();
		}

		/**
		 * @return Get the thread index from flag
		 */
		public int getThreadNum() {
			return first & 3;
		}

		public boolean isFrameThread() {
			return (fixData & 0x80) != 0;
		}

		public boolean isTargetThread() {
			return (fixData & 0x08) != 0;
		}

		public int getFrameMethod() {
			return fixData >> 4 & 7;
		}

		public int getFixThreadNum() {
			return fixData & 3;
		}

		public int getFixMethodWithSub(Subrecord rec) {
			return fixData & 0x04 | rec.getThreadMethod() & 0x3;
		}

		public int getFixMethod() {
			return fixData & 7;
		}

		public int getTargetDatum() {
			return targetDatum.value();
		}

		public int getTargetDisplacement() {
			return (int) targetDisplacement.value();
		}

		public int getLocationType() {
			return first >> 2 & 0xf;
		}

		public int getDataRecordOffset() {
			return (first & 3) << 8 | hiFixup & 0xff;
		}

		public boolean isSegmentRelative() {
			return (first & 0x40) != 0;
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return OmfUtils.toOmfRecordDataType(this, OmfRecordTypes.getName(recordType));
	}

}
