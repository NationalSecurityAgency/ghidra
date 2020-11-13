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
import java.io.RandomAccessFile;

/**
 * This class is responsible for reading pages from a {@link RandomAccessFile} for the
 *  {@link AbstractMsf} class and its underlying classes.
 */
class MsfFileReader implements AutoCloseable {

	//==============================================================================================
	// Internals
	//==============================================================================================
	private RandomAccessFile file;
	private AbstractMsf msf;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Closes this class, including its underlying file resources.
	 * @throws IOException Under circumstances found when closing a {@link RandomAccessFile}.
	 */
	@Override
	public void close() throws IOException {
		if (file != null) {
			file.close();
		}
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Constructor.
	 * @param msf The {@link AbstractMsf} for which this class is to be associated.
	 * @param file {@link RandomAccessFile} underlying this class.
	 */
	MsfFileReader(AbstractMsf msf, RandomAccessFile file) {
		this.msf = msf;
		this.file = file;
	}

	/**
	 * Reads a single page of bytes from the {@link AbstractMsf} and writes it into the bytes array.
	 * @param page The page number to read from the file.
	 * @param bytes The byte[] into which the data is to be written.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 */
	void readPage(int page, byte[] bytes) throws IOException {
		read(page, 0, msf.getPageSize(), bytes, 0);
	}

	/**
	 * Reads bytes from the {@link AbstractMsf} into a byte[].
	 * @param page The page number within which to start the read.
	 * @param offset The byte offset within the page to start the read.
	 * @param numToRead The total number of bytes to read.
	 * @param bytes The byte[] into which the data is to be written.
	 * @param bytesOffset The starting offset within the bytes array in which to start writing.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 */
	void read(int page, int offset, int numToRead, byte[] bytes, int bytesOffset)
			throws IOException {

		if (numToRead < 1) {
			throw new IOException("Must request at least one byte in MSF read");
		}

		if (offset < 0 || offset >= msf.getPageSize()) {
			throw new IOException(String.format("Offset must be in range [0, %d) in for MSF read",
				msf.getPageSize()));
		}

		// Calculate true offset within file.
		long fileOffset = offset + page * (long) msf.getPageSize();

		// Fail if file does not contain enough pages for the read--boundary case that assumes
		//  everything beyond the offset in the file belongs to this read.
		if (AbstractMsf.floorDivisionWithLog2Divisor(offset + numToRead,
			msf.getLog2PageSize()) > msf.getNumPages()) {
			throw new IOException("Invalid MSF configuration");
		}

		int numBytesRead = 0;
		file.seek(fileOffset);
		numBytesRead = file.read(bytes, bytesOffset, numToRead);

		if (numBytesRead != numToRead) {
			throw new IOException("Could not read required bytes from MSF");
		}
	}

}
