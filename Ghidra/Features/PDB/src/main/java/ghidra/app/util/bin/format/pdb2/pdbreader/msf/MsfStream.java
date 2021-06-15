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
package ghidra.app.util.bin.format.pdb2.pdbreader.msf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class representing a Stream within an {@link AbstractMsf}--see its write-up.
 * <P>
 * The stream can only be read, as it is part of a reader capability, not a read/write/modify
 *  capability.
 * <P>
 * The Stream can get initialized through a couple of mechanisms, but the essential information
 *  is the stream length, the map of stream page numbers to file page numbers, and the
 *  referenced {@link AbstractMsf} to which it belongs, which contains most other
 *  information that it needs.
 */
public class MsfStream {

	/**
	 * The maximum length of a stream that we currently allow under this design.
	 */
	public static final int MAX_STREAM_LENGTH = Integer.MAX_VALUE;

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected int streamLength;
	protected List<Integer> pageList = new ArrayList<>();
	protected AbstractMsf msf;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Returns the length of the Stream.
	 * @return Byte-length of Stream.
	 */
	public int getLength() {
		return streamLength;
	}

	/**
	 * Reads numToRead bytes from the stream starting at streamOffset within the stream.
	 *  Returns the byte array containing the read information. If not all bytes are available
	 *  to be read, an IOException will be thrown.
	 * @param streamOffset Location within the stream from where to start reading bytes.
	 * @param numToRead Number of bytes to read from the stream.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @return byte[] containing the bytes read.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws CancelledException Upon user cancellation.
	 */
	public byte[] read(int streamOffset, int numToRead, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (numToRead <= 0) {
			return null;
		}
		byte[] bytes = new byte[numToRead];
		read(streamOffset, bytes, 0, numToRead, monitor);
		return bytes;
	}

	/**
	 * Reads numToRead bytes from the stream starting at streamOffset within the stream.
	 *  The bytes are written into the bytes array starting at the bytesOffset location.
	 *  If not all bytes are available to be read, an IOException will be thrown.
	 * @param streamOffset Location within the stream from where to start reading bytes.
	 * @param bytes The array into which to write the data.
	 * @param bytesOffset The location within byte array at which to start writing data.
	 * @param numToRead Number of bytes to read from the stream.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws CancelledException Upon user cancellation.
	 */
	public void read(int streamOffset, byte[] bytes, int bytesOffset, int numToRead,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (streamOffset < 0 || streamOffset > streamLength) {
			throw new IOException("Offset out of range.");
		}
		if (numToRead > streamLength - streamOffset) {
			throw new IOException("Not enough data left.");
		}
		if (numToRead <= 0) {
			return;
		}

		int remainingByteCount = numToRead;
		int pageNumber = streamOffset >> msf.getLog2PageSize();
		int offsetIntoPage = streamOffset & msf.getPageSizeModMask();

		// Read any partial page at beginning first.
		if (offsetIntoPage != 0) {
			int firstNumToRead = Math.min(msf.getPageSize() - offsetIntoPage, remainingByteCount);
			msf.fileReader.read(pageList.get(pageNumber), offsetIntoPage, firstNumToRead, bytes,
				bytesOffset);
			if ((remainingByteCount - firstNumToRead) > remainingByteCount) {
				throw new IOException("Integer count underflow when preparing to read.");
			}
			remainingByteCount -= firstNumToRead;
			pageNumber++;
			bytesOffset += firstNumToRead;
		}
		// Read remaining pages, including last as possible partial page.
		// Outer loop iterates over possible non-sequential groups.
		while (remainingByteCount > 0) {
			monitor.checkCanceled();
			// Inner loop groups together sequential pages into one big read.
			int firstSequentialPageNumber = pageList.get(pageNumber);
			int lastSequentialPageNumber = firstSequentialPageNumber;
			int numToReadInSequentialPages = 0;
			do {
				monitor.checkCanceled();
				pageNumber++;
				lastSequentialPageNumber++;
				int numToReadInPage = Math.min(msf.getPageSize(), remainingByteCount);
				numToReadInSequentialPages += numToReadInPage;
				remainingByteCount -= numToReadInPage;
			}
			while (remainingByteCount > 0 && pageList.get(pageNumber) == lastSequentialPageNumber);
			msf.fileReader.read(firstSequentialPageNumber, 0, numToReadInSequentialPages, bytes,
				bytesOffset);
			bytesOffset += numToReadInSequentialPages;
		}
	}

	/**
	 * Debug method to dump the PDB Directory in a pretty format to String.
	 * @param maxOut Maximum number of bytes to output.
	 * @return {@link String} containing the pretty output.
	 */
	public String dump(int maxOut) {
		int outputLength = Math.min(getLength(), maxOut);
		StringBuilder builder = new StringBuilder();
		builder.append("Length: ");
		builder.append(getLength());
		builder.append(String.format(" (0x%08x)", getLength()));
		// If length is zero or negative (e.g., -1), done.
		if (outputLength <= 0) {
			return "";
		}
		byte[] bytes = new byte[outputLength];
		try {
			read(0, bytes, 0, outputLength, TaskMonitor.DUMMY);
		}
		catch (IOException e) {
			// Should not occur.  We limited our request to be <= the Stream length.
			throw new AssertException("Total bonkers: PDB Stream does not contain advertised data");
		}
		catch (CancelledException e) {
			// Should not occur.  We limited our request to be <= the Stream length.
			throw new AssertException("CancelledException Thrown");
		}
		for (int i = 0; i < outputLength;) {
			builder.append(String.format("\n%06x", i));
			for (int j = 0; (j < 16) && (i < outputLength); j++, i++) {
				builder.append(String.format(" %02x", bytes[i]));
			}
		}
		return builder.toString();
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Package-protected constructor of a PDB Stream.  Sets the byte length of the
	 * Stream to -1.  This method is used when the Stream knows/reads its length.
	 * @param msf The {@link AbstractMsf} to which the Stream belongs.
	 */
	MsfStream(AbstractMsf msf) {
		streamLength = -1;
		this.msf = msf;
	}

	/**
	 * Package-protected constructor of a PDB Stream.  This method is used when the
	 *  stream length comes from an external table.
	 * @param msf The {@link AbstractMsf} to which the Stream belongs.
	 * @param streamLength The byte length of the Stream.
	 */
	MsfStream(AbstractMsf msf, int streamLength) {
		this.msf = msf;
		this.streamLength = streamLength;
	}

	/**
	 * Deserializes Stream Length and an extra 4-byte field (which might be the address of the
	 *  map when it was previously stored in memory) from the bytes parameter starting at the
	 *  index offset and uses it to provide necessary information for the Stream to be usable.
	 *  Generally, deserialization is part of the step of loading the Stream information from
	 *  persistent storage (disk).
	 * @param reader {@link PdbByteReader} from which to parse the information.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	void deserializeStreamLengthAndMapTableAddress(PdbByteReader reader) throws PdbException {
		streamLength = reader.parseInt();
		// The next 4 bytes might be an address of the map table that got pushed to disk.
		reader.parseInt();
	}

	/**
	 * Deserializes Stream page number information from the bytes parameter starting at the
	 *  index offset and uses it to provide necessary information for the Stream to be usable.
	 *  Generally, deserialization is part of the step of loading the Stream information from
	 *  persistent storage (disk).
	 * @param reader {@link PdbByteReader} from which to parse the information.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	void deserializePageNumbers(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		// This calculations works fine for streamLength = 0
		//  and even streamLength = -1 (0xffffffff).
		int numPages =
			AbstractMsf.floorDivisionWithLog2Divisor(streamLength, msf.getLog2PageSize());
		if (msf.getPageNumberSize() == 2) {
			for (int i = 0; i < numPages; i++) {
				monitor.checkCanceled();
				int pageNumber = reader.parseUnsignedShortVal();
				if (pageNumber == 0) {
					break;
				}
				pageList.add(pageNumber);
			}
		}
		else if (msf.getPageNumberSize() == 4) {
			for (int i = 0; i < numPages; i++) {
				monitor.checkCanceled();
				int pageNumber = reader.parseInt();
				if (pageNumber == 0) {
					break;
				}
				pageList.add(pageNumber);
			}
		}
	}

	/**
	 * Deserializes Stream information from the bytes parameter starting at the index offset
	 *  and uses it to provide necessary information for the Stream to be usable.
	 *  Generally, deserialization is part of the step of loading the Stream information from
	 *  persistent storage (disk).
	 * @param reader {@link PdbByteReader} from which to parse the information.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	void deserializeStreamInfo(PdbByteReader reader, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		deserializeStreamLengthAndMapTableAddress(reader);
		deserializePageNumbers(reader, monitor);
	}

}
