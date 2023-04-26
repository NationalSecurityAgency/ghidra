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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * PDB C13 Module File Checksums.
 */
public class C13FileChecksums extends C13Section {

	private List<FileChecksum> fileChecksums = new ArrayList<>();

	/**
	 * Parse and return a {@link C13FileChecksums}.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize
	 * @param ignore flag indicating whether the record should be ignored
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return the parsed data
	 * @throws PdbException Upon not enough data left to parse
	 * @throws CancelledException Upon user cancellation
	 */
	static C13FileChecksums parse(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws PdbException, CancelledException {
		return new C13FileChecksums(reader, ignore, monitor);
	}

	protected C13FileChecksums(PdbByteReader reader, boolean ignore, TaskMonitor monitor)
			throws CancelledException, PdbException {
		super(ignore);
		while (reader.numRemaining() >= FileChecksum.getBaseRecordSize()) {
			monitor.checkCancelled();
			FileChecksum fileChecksum = new FileChecksum(reader);
			fileChecksums.add(fileChecksum);
		}
		if (reader.hasMore()) {
			Msg.debug(C13FileChecksums.class,
				String.format("Num Extra C13FileChecksums bytes: %d", reader.numRemaining()));
		}
	}

	public List<FileChecksum> getFileChecksums() {
		return fileChecksums;
	}

	@Override
	public String toString() {
		return String.format(
			"%s: num checksums = %d", getClass().getSimpleName(), fileChecksums.size());
	}

	/**
	 * Dumps this class to a Writer
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException Upon IOException writing to the {@link Writer}
	 */
	@Override
	void dump(Writer writer) throws IOException {
		writer.write("C13FileChecksums--------------------------------------------\n");
		for (FileChecksum checksum : fileChecksums) {
			writer.write(checksum.toString());
			writer.write('\n');
		}
		writer.write("End C13FileChecksums----------------------------------------\n");
	}

	static class FileChecksum {
		private long offsetFilename; // unsigned 32-bit
		private int length;
		private int checksumTypeValue;
		private byte[] bytes;

		private static int getBaseRecordSize() {
			return 6;
		}

		FileChecksum(PdbByteReader reader) throws PdbException {
			offsetFilename = reader.parseUnsignedIntVal();
			length = reader.parseUnsignedByteVal();
			checksumTypeValue = reader.parseUnsignedByteVal();
			bytes = reader.parseBytes(length);
			reader.align4();
		}

		long getOffsetFilename() {
			return offsetFilename;
		}

		long getLength() {
			return length;
		}

		long getChecksumTypeValue() {
			return checksumTypeValue;
		}

		byte[] getChecsumBytes() {
			return bytes;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(String.format("0x%08x, 0x%02x %s(%02x): ", offsetFilename, length,
				ChecksumType.fromValue(checksumTypeValue), checksumTypeValue));
			builder.append(NumericUtilities.convertBytesToString(bytes));
			return builder.toString();
		}
	}

	private static enum ChecksumType {
		UnknownChecksumType(-0x01),
		NoneChecksumType(0x00),
		Md5ChecksumType(0x01),
		Sha1ChecksumType(0x02),
		Sha256ChecksumType(0x03);

		private static final Map<Integer, ChecksumType> BY_VALUE = new HashMap<>();
		static {
			for (ChecksumType val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		private final int value;

		public static ChecksumType fromValue(int val) {
			ChecksumType t = BY_VALUE.getOrDefault(val, UnknownChecksumType);
			if (t == UnknownChecksumType && val != UnknownChecksumType.value) {
				Msg.warn(null,
					String.format("PDB: C13FileChecksum - Unknown checksum type %08x", val));
			}
			return t;
		}

		private ChecksumType(int value) {
			this.value = value;
		}
	}

}
