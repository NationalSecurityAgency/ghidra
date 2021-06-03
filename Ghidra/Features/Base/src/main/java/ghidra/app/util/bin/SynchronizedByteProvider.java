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

import ghidra.formats.gfilesystem.FSRL;

/**
 * Creates a thread-safe pass-through {@link ByteProvider}. 
 */
public class SynchronizedByteProvider implements ByteProvider {
	private final ByteProvider provider;

	/**
	 * Constructs a {@link SynchronizedByteProvider} around the specified {@link ByteProvider}
	 * 
	 * @param provider the {@link ByteProvider} to make thread-safe
	 */
	public SynchronizedByteProvider(ByteProvider provider) {
		this.provider = provider;
	}

	@Override
	public synchronized FSRL getFSRL() {
		return provider.getFSRL();
	}

	@Override
	public synchronized File getFile() {
		return provider.getFile();
	}

	@Override
	public synchronized String getName() {
		return provider.getName();
	}

	@Override
	public synchronized String getAbsolutePath() {
		return provider.getAbsolutePath();
	}

	@Override
	public synchronized long length() throws IOException {
		return provider.length();
	}

	@Override
	public synchronized boolean isValidIndex(long index) {
		return provider.isValidIndex(index);
	}

	@Override
	public synchronized void close() throws IOException {
		provider.close();
	}

	@Override
	public synchronized byte readByte(long index) throws IOException {
		return provider.readByte(index);
	}

	@Override
	public synchronized byte[] readBytes(long index, long length) throws IOException {
		return provider.readBytes(index, length);
	}

	@Override
	public synchronized InputStream getInputStream(long index) throws IOException {
		return provider.getInputStream(index);
	}
}
