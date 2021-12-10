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
package ghidra.file.formats.android.util;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;

/**
 * This byte provider is used to store decompressed chunks at specific locations.
 */
public class OverlayByteProvider implements ByteProvider {
	private ByteProvider provider;
	private List<OverlayRange> overlayList = new ArrayList<>();

	public OverlayByteProvider(ByteProvider provider) {
		this.provider = provider;
	}

	public void addRange(OverlayRange range) {
		overlayList.add(range);
	}

	@Override
	public File getFile() {
		return provider.getFile();
	}

	@Override
	public String getName() {
		return provider.getName();
	}

	@Override
	public String getAbsolutePath() {
		return provider.getAbsolutePath();
	}

	@Override
	public long length() throws IOException {
		long currentMax = 0;
		for (OverlayRange range : overlayList) {
			currentMax = Math.max(currentMax, range.getEndIndex());
		}
		return Math.max(currentMax, provider.length());
	}

	@Override
	public boolean isValidIndex(long index) {
		for (OverlayRange range : overlayList) {
			if (range.containsIndex(index)) {
				return true;
			}
		}
		return provider.isValidIndex(index);
	}

	@Override
	public void close() throws IOException {
		provider.close();
	}

	@Override
	public byte readByte(long index) throws IOException {
		for (OverlayRange range : overlayList) {
			if (range.containsIndex(index)) {
				return range.getByte(index);
			}
		}
		return provider.readByte(index);
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		for (OverlayRange range : overlayList) {
			if (range.containsIndex(index)) {
				return range.getBytes(index, length);
			}
		}
		return provider.readBytes(index, length);
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		throw new IOException("get input stream is not supported");
	}

}
