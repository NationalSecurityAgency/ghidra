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
package ghidra.file.formats.yaffs2;

import java.io.*;

public class YAFFS2InputStream implements Closeable {

	private int dataBufferSize = YAFFS2Constants.DATA_BUFFER_SIZE;
	private static int recordSize = YAFFS2Constants.RECORD_SIZE;
	private boolean hasHitEOF;
	private long entrySize;	// TODO: why is this a member var instead of local var?
	long fileEntryOffset;
	protected final YAFFS2Buffer buffer;
	private YAFFS2Entry currEntry;

	public YAFFS2InputStream(InputStream is) {
		this(is, recordSize);
	}

	public YAFFS2InputStream(InputStream is, int recordSize) {
		this.buffer = new YAFFS2Buffer(is, recordSize);
		this.hasHitEOF = false;
		this.fileEntryOffset = 0;
	}

	// get the next header, skipping the data block records
	public YAFFS2Entry getNextHeaderEntry() throws IOException {

		if (hasHitEOF) {
			return null;
		}

		// entry will be null on first try
		if (currEntry != null) {
			// if header is of type file, skip the data section to get to the next header object
			if (currEntry.isFile()) {
				long numToSkip = (recordSize) * (currEntry.getSize() / dataBufferSize) + recordSize;
				long skipped = buffer.skip(numToSkip);
				if (skipped < 0) {
					throw new RuntimeException("failed to skip current entry's data section");
				}
			}
		}

		// get a new YAFFS2 record
		byte[] headerBuf = getRecord();

		// check if we hit the EOF
		if (hasHitEOF) {
			currEntry = null;
			return null;
		}

		// parse the new buffer into a YAFFS2 entry
		currEntry = new YAFFS2Entry(headerBuf);

		// save where this entry is located in the image file
		currEntry.setFileOffset(fileEntryOffset);

		// compute the size of this entry
		entrySize = recordSize * (currEntry.getSize() / dataBufferSize) + recordSize;
		if (currEntry.isFile()) {
			entrySize = entrySize + recordSize;
		}

		// compute where the next entry starts in the image file
		fileEntryOffset = fileEntryOffset + entrySize;

		return currEntry;
	}

	// get data for the selected file - skip to offset and return length bytes
	public byte[] getEntryData(long offset, long length) throws IOException {

		long numberOfBuffers = length / dataBufferSize;
		long remainder = length % dataBufferSize;
		long numberToRead = recordSize * numberOfBuffers + remainder;
		int indx = 0;
		byte[] contents = new byte[(int) numberToRead];
		entrySize = offset + recordSize;

		// skip to correct file location (offset gets us to the header, recordSize gets past that header to the start of data)
		long skipped = buffer.skip(offset + recordSize);
		if (skipped < 0) {
			throw new RuntimeException("failed to skip to the data section");
		}

		// read fully populated buffers of data
		while (numberOfBuffers > 0) {
			byte[] dataBuf = getRecord();
			System.arraycopy(dataBuf, 0, contents, indx, dataBufferSize);
			numberOfBuffers -= 1;
			indx += dataBufferSize;
		}

		// read another partial record?
		if (remainder > 0) {
			byte[] dataBuf = getRecord();
			System.arraycopy(dataBuf, 0, contents, indx, (int) remainder);
		}

		return contents;
	}

	private byte[] getRecord() throws IOException {
		if (hasHitEOF) {
			return null;
		}

		byte[] headerBuf = buffer.readRecord();

		// check if we hit the end of file
		if (headerBuf == null) {
			hasHitEOF = true;
		}
		else if (buffer.isEOFRecord(headerBuf)) {
			hasHitEOF = true;
		}

		// return null for EOF, the record if not
		return hasHitEOF ? null : headerBuf;
	}

	@Override
	public void close() throws IOException {
		buffer.close();
	}

}
