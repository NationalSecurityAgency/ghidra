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
package pdb.symbolserver;

import java.io.*;

/**
 * A {@link InputStream} wrapper returned from a {@link SymbolServer}
 * that also contains the expected length of the stream.
 */
public class SymbolServerInputStream implements Closeable {
	private final InputStream inputStream;
	private final long expectedLength;

	/**
	 * Create a new instance.
	 * 
	 * @param inputStream {@link InputStream} to wrap
	 * @param expectedLength the expected length of the input stream
	 */
	public SymbolServerInputStream(InputStream inputStream, long expectedLength) {
		this.inputStream = inputStream;
		this.expectedLength = expectedLength;
	}

	/**
	 * Returns the wrapped input stream
	 * @return the wrapped input stream
	 */
	public InputStream getInputStream() {
		return inputStream;
	}

	/**
	 * Returns the expected length of the input stream
	 * 
	 * @return expected length of the input stream
	 */
	public long getExpectedLength() {
		return expectedLength;
	}

	@Override
	public void close() throws IOException {
		inputStream.close();
	}
}
