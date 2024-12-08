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

import java.io.*;

/**
 * An {@link InputStream} wrapper that keeps a {@link FileSystemRef} pinned.
 */
public class RefdInputStream extends InputStream {

	private FileSystemRef fsRef;
	private InputStream delegate;

	/**
	 * Creates a new {@link RefdInputStream}.
	 * 
	 * @param fsRef {@link FileSystemRef}
	 * @param delegate the wrapped {@link InputStream}
	 */
	public RefdInputStream(FileSystemRef fsRef, InputStream delegate) {
		this.fsRef = fsRef;
		this.delegate = delegate;
	}

	@Override
	public void close() throws IOException {
		if (fsRef != null) {
			fsRef.close();
			fsRef = null;
		}
		delegate.close();
	}

	@Override
	public int available() throws IOException {
		return delegate.available();
	}

	@Override
	public int read() throws IOException {
		return delegate.read();
	}

	@Override
	public int read(byte[] b) throws IOException {
		return delegate.read(b);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		return delegate.read(b, off, len);
	}

	@Override
	public byte[] readAllBytes() throws IOException {
		return delegate.readAllBytes();
	}

	@Override
	public int readNBytes(byte[] b, int off, int len) throws IOException {
		return delegate.readNBytes(b, off, len);
	}

	@Override
	public byte[] readNBytes(int len) throws IOException {
		return delegate.readNBytes(len);
	}

	@Override
	public synchronized void mark(int readlimit) {
		delegate.mark(readlimit);
	}

	@Override
	public boolean markSupported() {
		return delegate.markSupported();
	}

	@Override
	public long skip(long n) throws IOException {
		return delegate.skip(n);
	}

	@Override
	public synchronized void reset() throws IOException {
		delegate.reset();
	}

	@Override
	public long transferTo(OutputStream out) throws IOException {
		return delegate.transferTo(out);
	}

	@Override
	public void skipNBytes(long n) throws IOException {
		delegate.skipNBytes(n);
	}

}
