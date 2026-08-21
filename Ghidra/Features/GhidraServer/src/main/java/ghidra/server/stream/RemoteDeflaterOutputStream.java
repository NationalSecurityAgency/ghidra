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
package ghidra.server.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * {@link RemoteDeflaterOutputStream} extends {@link DeflaterOutputStream} and
 * allows a non-default {@link Deflater} to "end" properly when this output stream
 * is closed.
 */
class RemoteDeflaterOutputStream extends DeflaterOutputStream {

	private boolean closed = false;

	/**
	 * Construct a deflater output stream using a specified compression level.
	 * @param out output stream providing the uncompressed data
	 * @param deflaterLevel {@link Deflater} compression level
	 */
	RemoteDeflaterOutputStream(OutputStream out, int deflaterLevel) {
		super(out, new Deflater(deflaterLevel));
	}

	@Override
	public void close() throws IOException {
		if (!closed) {
			try {
				super.close();
			}
			finally {
				closed = true;
				def.end(); // Must end on close since we did not use default Deflater
			}
		}
	}
}
