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

// a method to return a single YAFFS2 record
public class YAFFS2Buffer {

	private static int recordSize = YAFFS2Constants.RECORD_SIZE;
	private InputStream inStream;
	private OutputStream outStream;
	private byte[] recordBuffer;

	public YAFFS2Buffer(InputStream inStream) {
		this(inStream, recordSize);
	}

	public YAFFS2Buffer(InputStream inStream, int recordSize) {
		this.inStream = inStream;
		this.outStream = null;
		this.initialize(recordSize);
	}

	private void initialize(int recordSize) {
		this.recordBuffer = new byte[recordSize];
	}

	public byte[] readRecord() throws IOException {
		if (inStream == null) {
			if (outStream == null) {
				throw new IOException("input buffer is closed");
			}
			throw new IOException("reading from an output buffer");
		}
		long numBytes = inStream.read(recordBuffer, 0, recordSize);
		if (numBytes == -1) {
			return null;
		}
		return recordBuffer;
	}

	public long skip(long numToSkip) throws IOException {
		return inStream.skip(numToSkip);
	}

	public boolean isEOFRecord(byte[] record) {
		for (int i = 0, sz = getRecordSize(); i < sz; ++i) {
			if (record[i] != 0) {
				return false;
			}
		}
		return true;
	}

	public int getRecordSize() {
		return recordSize;
	}

	public void close() throws IOException {
		if (inStream != System.in) {
			inStream.close();
		}
		inStream = null;
	}

}
