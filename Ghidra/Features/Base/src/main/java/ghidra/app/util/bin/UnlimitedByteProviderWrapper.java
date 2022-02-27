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

import java.io.IOException;

import ghidra.formats.gfilesystem.FSRL;

/**
 * A {@link ByteProvider} constrained to a sub-section of an existing {@link ByteProvider}
 * although reads beyond the specified sub-section are permitted but will return zero byte
 * values.  The methods {@link #length()} and {@link #getInputStream(long)} remain
 * bounded by the specified sub-section.
 */
public class UnlimitedByteProviderWrapper extends ByteProviderWrapper {

	/**
	 * Creates a wrapper around a {@link ByteProvider} that contains the same bytes as the specified
	 * provider.
	 * <p>
	 * 
	 * @param provider {@link ByteProvider} to wrap
	 * @throws IOException if error
	 */
	public UnlimitedByteProviderWrapper(ByteProvider provider) throws IOException {
		this(provider, 0, provider.length(), provider.getFSRL());
	}

	/**
	 * Creates a wrapper around a {@link ByteProvider} that contains the same bytes as the specified
	 * provider, but with a new {@link FSRL} identity.
	 * <p>
	 * 
	 * @param provider {@link ByteProvider} to wrap
	 * @param fsrl {@link FSRL} identity for the instance
	 * @throws IOException if error
	 */
	public UnlimitedByteProviderWrapper(ByteProvider provider, FSRL fsrl) throws IOException {
		this(provider, 0, provider.length(), fsrl);
	}

	/**
	 * Constructs a {@link UnlimitedByteProviderWrapper} around the specified {@link ByteProvider},
	 * constrained to a subsection of the provider.
	 * 
	 * @param provider the {@link ByteProvider} to wrap
	 * @param subOffset the offset in the {@link ByteProvider} of where to start the new
	 *   {@link UnlimitedByteProviderWrapper} 
	 * @param subLength the length of the new {@link UnlimitedByteProviderWrapper} 
	 */
	public UnlimitedByteProviderWrapper(ByteProvider provider, long subOffset, long subLength) {
		this(provider, subOffset, subLength, null);
	}

	/**
	 * Constructs a {@link UnlimitedByteProviderWrapper} around the specified {@link ByteProvider},
	 * constrained to a subsection of the provider.
	 * 
	 * @param provider the {@link ByteProvider} to wrap
	 * @param subOffset the offset in the {@link ByteProvider} of where to start the new
	 *   {@link UnlimitedByteProviderWrapper} 
	 * @param subLength the length of the new {@link UnlimitedByteProviderWrapper} 
	 * @param fsrl {@link FSRL} identity of the file this ByteProvider represents
	 */
	public UnlimitedByteProviderWrapper(ByteProvider provider, long subOffset, long subLength, FSRL fsrl) {
		super(provider, subOffset, subLength, fsrl);
	}

	@Override
	public boolean isValidIndex(long index) {
		return index >= 0;
	}

	@Override
	public byte readByte(long index) throws IOException {
		if (index < 0) {
			throw new IOException("Invalid index: " + index);
		}
		if (index >= subLength) {
			return 0;
		}
		return provider.readByte(subOffset + index);
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		if (index < 0) {
			throw new IOException("Invalid index: " + index);
		}
		if (index >= subLength) {
			return new byte[(int) length];
		}
		if (index + length > subLength) {
			byte[] bytes = new byte[(int) length];
			byte[] partialBytes = provider.readBytes(subOffset + index, subLength - index);
			System.arraycopy(partialBytes, 0, bytes, 0, partialBytes.length);
			return bytes;
		}
		return provider.readBytes(subOffset + index, length);
	}
}
