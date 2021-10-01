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
package ghidra.file.formats.sevenzip;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import net.sf.sevenzipjbinding.IInStream;
import net.sf.sevenzipjbinding.SevenZipException;

/**
 * Adapter from Ghidra's {@link ByteProvider} to SZ's {@link IInStream}
 */
class SZByteProviderStream implements IInStream {

	private ByteProvider bp;
	private long position;

	SZByteProviderStream(ByteProvider bp) {
		this.bp = bp;
	}

	@Override
	public synchronized long seek(long offset, int seekOrigin) throws SevenZipException {
		try {
			switch (seekOrigin) {
				case SEEK_SET:
					setPos(offset);
					break;

				case SEEK_CUR:
					setPos(position + offset);
					break;

				case SEEK_END:
					setPos(bp.length() + offset);
					break;

				default:
					throw new RuntimeException("Seek: unknown origin: " + seekOrigin);
			}
		}
		catch (IOException e) {
			throw new SevenZipException(e);
		}

		return position;
	}

	private void setPos(long newPos) throws SevenZipException {
		if (newPos < 0) {
			throw new SevenZipException("Invalid offset: " + newPos);
		}
		position = newPos;
	}

	@Override
	public synchronized int read(byte[] data) throws SevenZipException {
		try {
			int bytesToRead = (int)Math.min(data.length, bp.length() - position);
			if (bytesToRead <= 0) {
				return 0;
			}
			byte[] bytes = bp.readBytes(position, bytesToRead);
			System.arraycopy(bytes, 0, data, 0, bytes.length);

			position += bytes.length;
			return bytes.length;
		}
		catch (IOException e) {
			throw new SevenZipException("Error reading random access file", e);
		}
	}

	@Override
	public void close() throws IOException {
		bp.close();
	}

}
