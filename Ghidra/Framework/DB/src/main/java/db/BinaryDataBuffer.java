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
package db;

import db.buffers.DataBuffer;

/**
 * Provides data buffer for encoding use.
 */
class BinaryDataBuffer extends DataBuffer {

	/**
	 * Construct a data buffer.
	 * 
	 * @see db.buffers.DataBuffer#DataBuffer(byte[])
	 */
	BinaryDataBuffer(byte[] data) {
		super(data);
	}

	/**
	 * Construct a data buffer.
	 * 
	 * @see db.buffers.DataBuffer#DataBuffer(int)
	 */
	BinaryDataBuffer(int size) {
		super(size);
	}

	/**
	 * Get the byte storage array associated with this buffer.
	 * 
	 * @return byte storage array.
	 */
	@Override
    protected byte[] getData() {
		return data;
	}

}
