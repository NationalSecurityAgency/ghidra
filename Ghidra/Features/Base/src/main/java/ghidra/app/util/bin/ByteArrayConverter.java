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

import ghidra.util.DataConverter;

import java.io.IOException;

/**
 * An interface to convert from a object to a
 * byte array.
 * 
 */
public interface ByteArrayConverter {
	/**
	 * Returns a byte array representing this implementor
	 * of this interface.
	 * @param dc the data converter to use
	 * @return a byte array representing this object
	 */
	public byte [] toBytes(DataConverter dc) throws IOException;
}
