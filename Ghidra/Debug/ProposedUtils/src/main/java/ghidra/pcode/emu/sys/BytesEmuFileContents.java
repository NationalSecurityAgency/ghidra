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
package ghidra.pcode.emu.sys;

/**
 * A concrete in-memory bytes store for simulated file contents
 * 
 * <p>
 * Note that currently, the total contents cannot exceed a Java array, so the file must remain less
 * than 2GB in size.
 */
public class BytesEmuFileContents implements EmuFileContents<byte[]> {
	protected static final int INIT_CONTENT_SIZE = 1024;

	protected byte[] content = new byte[INIT_CONTENT_SIZE];

	@Override
	public synchronized long read(long offset, byte[] buf, long fileSize) {
		// We're using an in-memory array, so limited to int offsets
		if (offset > Integer.MAX_VALUE) {
			throw new EmuIOException("Offset is past end of file");
		}
		long len = Math.min(buf.length, fileSize - offset);
		if (len < 0) {
			throw new EmuIOException("Offset is past end of file");
		}
		System.arraycopy(content, (int) offset, buf, 0, (int) len);
		return len;
	}

	@Override
	public synchronized long write(long offset, byte[] buf, long curSize) {
		long newSize = offset + buf.length;
		if (newSize > Integer.MAX_VALUE || newSize < 0) {
			throw new EmuIOException("File size cannot exceed " + Integer.MAX_VALUE + " bytes");
		}
		if (newSize > content.length) {
			byte[] grown = new byte[content.length * 2];
			System.arraycopy(content, 0, grown, 0, (int) curSize);
			content = grown;
		}
		System.arraycopy(buf, 0, content, (int) offset, buf.length);
		return buf.length;
	}

	@Override
	public synchronized void truncate() {
		if (content.length > INIT_CONTENT_SIZE) {
			content = new byte[INIT_CONTENT_SIZE];
		}
	}
}
