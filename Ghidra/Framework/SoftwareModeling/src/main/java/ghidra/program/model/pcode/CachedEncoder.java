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

import java.io.IOException;
import java.io.OutputStream;

/**
 * An Encoder that holds its bytes in memory (where they can possibly be edited) and
 * can then finally write them all to an OutputStream via a call to writeTo()
 */
public interface CachedEncoder extends Encoder {

	/**
	 * Clear any state associated with the encoder
	 * The encoder should be ready to write a new document after this call.
	 */
	void clear();

	/**
	 * The encoder is considered empty if the writeTo() method would output zero bytes
	 * @return true if there are no bytes in the encoder
	 */
	public boolean isEmpty();

	/**
	 * Dump all the accumulated bytes in this encoder to the stream.
	 * @param stream is the output stream
	 * @throws IOException for errors during the write operation
	 */
	public void writeTo(OutputStream stream) throws IOException;
}
