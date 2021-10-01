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
 * A {@link ByteProvider} that has no contents.
 * 
 */
public class EmptyByteProvider implements ByteProvider {

	private final FSRL fsrl;

	/**
	 * Create an instance with a null identity
	 */
	public EmptyByteProvider() {
		this(null);
	}

	/**
	 * Create an instance with the specified {@link FSRL} identity.
	 * 
	 * @param fsrl {@link FSRL} identity for this instance
	 */
	public EmptyByteProvider(FSRL fsrl) {
		this.fsrl = fsrl;
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public String getName() {
		return fsrl != null ? fsrl.getName() : null;
	}

	@Override
	public String getAbsolutePath() {
		return fsrl != null ? fsrl.getPath() : null;
	}

	@Override
	public byte readByte(long index) throws IOException {
		throw new IOException("Not supported");
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		if (index != 0 || length != 0) {
			throw new IOException("Not supported");
		}
		return new byte[0];
	}

	@Override
	public long length() {
		return 0;
	}

	@Override
	public boolean isValidIndex(long index) {
		return false;
	}

	@Override
	public void close() throws IOException {
		// do nothing
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		if (index != 0) {
			throw new IOException("Invalid offset");
		}
		return InputStream.nullInputStream();
	}


}
