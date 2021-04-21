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
import java.util.Map.Entry;
import java.util.TreeMap;

import ghidra.formats.gfilesystem.FSRL;

/**
 * A {@link ByteProvider} that is a concatenation of sub-ranges of another ByteProvider, also
 * allowing for non-initialized (sparse) regions.
 * <p> 
 * Not thread-safe when extents are being added. 
 */
public class ExtentsByteProvider implements ByteProvider {

	private ByteProvider delegate;
	/**
	 * TreeMap of this-provider offsets to the delegate-provider's offsets.
	 * <p>
	 * Each extent/region in the delegate provider is defined by the gap between
	 * adjacent offsetMap entries.  The last entry is bounded by the total
	 * length of the provider as specified by the length field. 
	 */
	private TreeMap<Long, Long> offsetMap = new TreeMap<>(); // this-provider offset -> delegate-provider offset
	private long length;
	private FSRL fsrl;

	/**
	 * Creates a new {@link ExtentsByteProvider}.
	 * 
	 * @param provider {@link ByteProvider} to wrap
	 * @param fsrl {@link FSRL} of the byte provider
	 */
	public ExtentsByteProvider(ByteProvider provider, FSRL fsrl) {
		this.delegate = provider;
		this.fsrl = fsrl;
	}

	/**
	 * Adds an extent to the current end of this instance.
	 * 
	 * @param offset long byte offset in the delegate ByteProvider
	 * @param extentLen long length of the extent region in the delegate ByteProvider
	 */
	public void addExtent(long offset, long extentLen) {
		if (extentLen <= 0) {
			throw new IllegalArgumentException();
		}
		offsetMap.put(length, offset);
		length += extentLen;
	}

	/**
	 * Adds a sparse extent to the current end of this instance.
	 * 
	 * @param extentLen long length of the sparse extent region
	 */
	public void addSparseExtent(long extentLen) {
		addExtent(-1, extentLen);
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public String getName() {
		return null;
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	@Override
	public String getAbsolutePath() {
		return null;
	}

	@Override
	public long length() throws IOException {
		return length;
	}

	@Override
	public boolean isValidIndex(long index) {
		return 0 <= index && index < length;
	}

	@Override
	public void close() throws IOException {
		delegate.close();
	}

	@Override
	public byte readByte(long index) throws IOException {
		ensureBounds(index, 1);

		Entry<Long, Long> entry = offsetMap.floorEntry(index);
		long extentStart = entry.getKey();
		long extentOffset = index - extentStart;
		long delegateExtentStart = entry.getValue();

		return (delegateExtentStart != -1)
				? delegate.readByte(delegateExtentStart + extentOffset)
				: 0;
	}

	@Override
	public byte[] readBytes(long index, long longCount) throws IOException {
		if (longCount >= Integer.MAX_VALUE) {
			throw new IOException("Unable to read " + longCount + " bytes at once");
		}
		ensureBounds(index, longCount);

		int count = (int) longCount;
		byte[] result = new byte[count];
		int bytesRead = 0;
		while (bytesRead < count) {
			long offsetToRead = index + bytesRead;
			Entry<Long, Long> entry = offsetMap.floorEntry(offsetToRead);
			Entry<Long, Long> nextEntry = offsetMap.higherEntry(entry.getKey());

			long extentStart = entry.getKey();
			long extentOffset = offsetToRead - extentStart;
			long extentEnd = (nextEntry != null) ? nextEntry.getKey() : length;
			long delegateExtentStart = entry.getValue();
			int bytesToRead =
				(int) Math.min(count - bytesRead, extentEnd - extentStart - extentOffset);
			if (delegateExtentStart != -1) {
				long delegateOffsetToRead = delegateExtentStart + extentOffset;
				byte[] extentBytes = delegate.readBytes(delegateOffsetToRead, bytesToRead);
				System.arraycopy(extentBytes, 0, result, bytesRead, bytesToRead);
			}
			else {
				// the extent was not present, result will be 0's
			}
			bytesRead += bytesToRead;
		}
		return result;
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		return new ByteProviderInputStream(this, 0, length);
	}

	private void ensureBounds(long index, long count) throws IOException {
		if (index < 0 || index > length) {
			throw new IOException("Invalid index: " + index);
		}
		if (index + count > length) {
			throw new IOException("Unable to read past EOF: " + index + ", " + count);
		}
	}

}
