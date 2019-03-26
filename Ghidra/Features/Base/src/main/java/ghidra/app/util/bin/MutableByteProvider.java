/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.io.IOException;

/**
 * An interface for a generic random-access byte provider, plus mutation methods.
 */
public interface MutableByteProvider extends ByteProvider {
	/**
	 * Writes a byte at the specified index.
	 * @param index the index to write the byte
	 * @param value the value to write at the specified index
	 * @throws IOException if an I/O error occurs
	 */
	public void writeByte(long index, byte value) throws IOException;

	/**
	 * Writes a byte array at the specified index.
	 * @param index the index to write the byte array
	 * @param values the values to write at the specified index
	 * @throws IOException if an I/O error occurs
	 */
	public void writeBytes(long index, byte[] values) throws IOException;
}
