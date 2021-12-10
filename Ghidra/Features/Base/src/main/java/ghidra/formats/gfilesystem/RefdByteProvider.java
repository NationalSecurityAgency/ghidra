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
package ghidra.formats.gfilesystem;

import java.io.File;
import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;

/**
 * A {@link ByteProvider} along with a {@link FileSystemRef} to keep the filesystem pinned
 * in memory.
 * <p>
 * The caller is responsible for {@link #close() closing} this object, which releases
 * the FilesystemRef.
 */
public class RefdByteProvider implements ByteProvider {
	private final FileSystemRef fsRef;
	private final ByteProvider provider;
	private final FSRL fsrl;

	/**
	 * Creates a RefdByteProvider instance, taking ownership of the supplied FileSystemRef.
	 * 
	 * @param fsRef {@link FileSystemRef} that contains the specified ByteProvider
	 * @param provider {@link ByteProvider} inside the filesystem held open by the ref
	 * @param fsrl {@link FSRL} identity of this new ByteProvider
	 */
	public RefdByteProvider(FileSystemRef fsRef, ByteProvider provider, FSRL fsrl) {
		this.fsRef = fsRef;
		this.provider = provider;
		this.fsrl = fsrl;
	}

	@Override
	public void close() throws IOException {
		provider.close();
		fsRef.close();
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	@Override
	public File getFile() {
		return provider.getFile();
	}

	@Override
	public String getName() {
		return fsrl != null ? fsrl.getName() : provider.getName();
	}

	@Override
	public String getAbsolutePath() {
		return fsrl != null ? fsrl.getPath() : provider.getAbsolutePath();
	}

	@Override
	public long length() throws IOException {
		return provider.length();
	}

	@Override
	public boolean isValidIndex(long index) {
		return provider.isValidIndex(index);
	}

	@Override
	public byte readByte(long index) throws IOException {
		return provider.readByte(index);
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		return provider.readBytes(index, length);
	}

	@Override
	public String toString() {
		return "ByteProvider " + provider.getFSRL() + " in file system " + fsRef.getFilesystem();
	}
}
