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
package ghidra.app.util.bin.format.macos.rm;

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

/**
 * Format of resource data for a single resource.
 */
public class SingleResourceData {
	private int length;
	private byte [] data = new byte[0];

	public SingleResourceData(BinaryReader reader) throws IOException {
		length = reader.readNextInt();
		data = reader.readNextByteArray(length);
	}

	/**
	 * Returns the length of the following resource.
	 * @return the length of the following resource
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Returns the resource data for this resource.
	 * @return the resource data for this resource
	 */
	public byte [] getData() {
		return data;
	}
}
