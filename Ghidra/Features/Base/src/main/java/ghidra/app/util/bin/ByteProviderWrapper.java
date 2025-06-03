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

import java.io.File;
import java.io.IOException;

import ghidra.formats.gfilesystem.FSRL;

/**
 * A {@link ByteProvider} constrained to a sub-section of an existing {@link ByteProvider}.
 */
public class ByteProviderWrapper implements ByteProvider {

	protected final ByteProvider provider;
	protected final long subOffset;
	protected final long subLength;
	protected final FSRL fsrl;

	/**
	 * Creates a wrapper around a {@link ByteProvider} that contains the same bytes as the specified
	 * provider, but with a new {@link FSRL} identity.
	 * 
	 * @param provider {@link ByteProvider} to wrap
	 * @param fsrl {@link FSRL} identity for the instance
	 * @throws IOException if error
	 */
	public ByteProviderWrapper(ByteProvider provider, FSRL fsrl) throws IOException {
		this(provider, 0, provider.length(), fsrl);
	}

	/**
	 * Constructs a {@link ByteProviderWrapper} around the specified {@link ByteProvider},
	 * constrained to a subsection of the provider.
	 * 
	 * @param provider the {@link ByteProvider} to wrap
	 * @param subOffset the offset in the {@link ByteProvider} of where to start the new
	 *   {@link ByteProviderWrapper} 
	 * @param subLength the length of the new {@link ByteProviderWrapper} 
	 */
	public ByteProviderWrapper(ByteProvider provider, long subOffset, long subLength) {
		this(provider, subOffset, subLength, null);
	}

	/**
	 * Constructs a {@link ByteProviderWrapper} around the specified {@link ByteProvider},
	 * constrained to a subsection of the provider.
	 * 
	 * @param provider the {@link ByteProvider} to wrap
	 * @param subOffset the offset in the {@link ByteProvider} of where to start the new
	 *   {@link ByteProviderWrapper} 
	 * @param subLength the length of the new {@link ByteProviderWrapper} 
	 * @param fsrl {@link FSRL} identity of the file this ByteProvider represents
	 */
	public ByteProviderWrapper(ByteProvider provider, long subOffset, long subLength, FSRL fsrl) {
		this.provider = provider;
		this.subOffset = subOffset;
		this.subLength = subLength;
		this.fsrl = fsrl;
	}

	@Override
	public void close() throws IOException {
		// do not close the wrapped provider
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	@Override
	public File getFile() {
		// there is no file that represents the actual contents of the subrange, so return null
		return null;
	}

	@Override
	public String getName() {
		return (fsrl != null)
				? fsrl.getName()
				: String.format("%s[0x%x,0x%x]", provider.getName(), subOffset, subLength);
	}

	@Override
	public String getAbsolutePath() {
		return (fsrl != null)
				? fsrl.getPath()
				: String.format("%s[0x%x,0x%x]", provider.getAbsolutePath(), subOffset, subLength);
	}

	@Override
	public long length() throws IOException {
		return subLength;
	}

	@Override
	public boolean isValidIndex(long index) {
		return (0 <= index && index < subLength) && provider.isValidIndex(subOffset + index);
	}

	@Override
	public byte readByte(long index) throws IOException {
		if (index < 0 || index >= subLength) {
			throw new IOException("Invalid index: " + index);
		}
		return provider.readByte(subOffset + index);
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		if (index < 0 || index >= subLength) {
			throw new IOException("Invalid index: " + index);
		}
		if (index + length > subLength) {
			throw new IOException("Unable to read past EOF: " + index + ", " + length);
		}
		return provider.readBytes(subOffset + index, length);
	}
}
