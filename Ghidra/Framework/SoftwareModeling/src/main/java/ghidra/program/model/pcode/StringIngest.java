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
package ghidra.program.model.pcode;

import java.io.*;

public class StringIngest implements ByteIngest {

	private ByteArrayOutputStream outStream;
	private String description;		// Describes the source of bytes, for use in error messages 
	private int maxBytes;			// Maximum number of bytes that can be ingested

	public StringIngest() {
		outStream = null;
		description = null;
		maxBytes = 0;
	}

	@Override
	public void open(int max, String desc) {
		maxBytes = max;
		description = desc;
		outStream = new ByteArrayOutputStream();
	}

	@Override
	public void ingestStreamToNextTerminator(InputStream inStream) throws IOException {
		int tok = inStream.read();
		while (tok > 0) {
			outStream.write(tok);
			if (outStream.size() >= maxBytes) {
				throw new IOException("Buffer size exceeded: " + description);
			}
			tok = inStream.read();
		}
	}

	@Override
	public void ingestStream(InputStream inStream) throws IOException {
		throw new IOException("Not supported");
	}

	@Override
	public void ingestBytes(byte[] byteArray, int off, int sz) throws IOException {
		for (int i = 0; i < sz; ++i) {
			int tok = byteArray[off + i];
			outStream.write(tok);
			if (outStream.size() >= maxBytes) {
				throw new IOException("Buffer size exceeded: " + description);
			}
		}
	}

	@Override
	public void endIngest() {
		// Nothing needs to be done
	}

	@Override
	public void clear() {
		outStream = null;
		description = null;
	}

	@Override
	public String toString() {
		if (outStream == null) {
			return "<empty>";
		}
		return outStream.toString();
	}

	@Override
	public boolean isEmpty() {
		return outStream == null || (outStream.size() == 0);
	}
}
