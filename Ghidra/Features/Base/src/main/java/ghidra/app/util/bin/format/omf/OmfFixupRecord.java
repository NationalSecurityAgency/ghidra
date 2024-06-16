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

public class OmfFixupRecord extends OmfRecord {
	private final Subrecord[] subrecs;
	private OmfData lastData = null;

	/**
	 * Read a Fixup record from the input reader
	 * @param reader The actual reader
	 * @throws IOException
	 */
	public OmfFixupRecord(BinaryReader reader) throws IOException {
		ArrayList<Subrecord> subreclist = new ArrayList<Subrecord>();

		readRecordHeader(reader);
		long max = reader.getPointerIndex() + getRecordLength() - 1;
		while (reader.getPointerIndex() < max) {
			subreclist.add(Subrecord.readSubrecord(reader, hasBigFields()));
		}
		subrecs = new Subrecord[subreclist.size()];
		subreclist.toArray(subrecs);
		readCheckSumByte(reader);
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

	public static class Subrecord {
		private byte first;
		private byte hiFixup;
		private byte fixData;
		private int index;
		private int frameDatum;
		private int targetDatum;
		private int targetDisplacement;

		/**
		 * Read the next subrecord from the input reader
		 *
		 * @param reader The input file
		 * @param hasBigFields Is this 16 or 32 bit values
		 * @return The read subrecord
		 * @throws IOException
		 */
		public static Subrecord readSubrecord(BinaryReader reader, boolean hasBigFields)
				throws IOException {
			int method;
			final var rec = new Subrecord();
			rec.first = reader.readNextByte();
			rec.index = -1;
			if (rec.isThreadSubrecord()) {
				method = rec.getThreadMethod();
				if (method < 4) {
					rec.index = readIndex(reader);
				}
				return rec;
			}
			rec.targetDisplacement = 0;
			rec.targetDatum = 0;
			rec.hiFixup = reader.readNextByte();
			rec.fixData = reader.readNextByte();
			method = rec.getFrameMethod();
			if (!rec.isFrameThread() && method < 3) { // F=0  (explicit frame method (and datum))
				rec.frameDatum = readIndex(reader);
			}
			if (!rec.isTargetThread()) { // T=0  (explicit target)
				rec.targetDatum = readIndex(reader);
			}
			if ((rec.fixData & 0x04) == 0) { // P=0
				rec.targetDisplacement = readInt2Or4(reader, hasBigFields);
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
			return index;
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
			return targetDatum;
		}

		public int getTargetDisplacement() {
			return targetDisplacement;
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

}
