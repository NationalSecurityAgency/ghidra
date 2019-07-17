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
package ghidra.app.util.bin;

import java.io.*;

/**
 * Creates a byte provider constrained to a sub-section
 * of an existing byte provider.
 */
public class ByteProviderWrapper implements ByteProvider {
	private ByteProvider provider;
	private long subOffset;
	private long subLength;

	public ByteProviderWrapper(ByteProvider provider, long subOffset, long subLength) {
		this.provider = provider;
		this.subOffset = subOffset;
		this.subLength = subLength;
	}

	@Override
	public void close() {
		// don't do anything for now
	}

	@Override
	public File getFile() {
		return provider.getFile();
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		return provider.getInputStream(subOffset + index);
	}

	@Override
	public String getName() {
		return provider.getName() + "[0x" + Long.toHexString(subOffset) + ",0x" +
			Long.toHexString(subLength) + "]";
	}

	@Override
	public String getAbsolutePath() {
		return provider.getAbsolutePath() + "[0x" + Long.toHexString(subOffset) + ",0x" +
			Long.toHexString(subLength) + "]";
	}

	@Override
	public long length() throws IOException {
		return subLength;
	}

	@Override
	public boolean isValidIndex(long index) {
		if (provider.isValidIndex(index)) {
			return index >= subOffset && index < subLength;
		}
		return false;
	}

	@Override
	public byte readByte(long index) throws IOException {
		return provider.readByte(subOffset + index);
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		return provider.readBytes(subOffset + index, length);
	}
}
