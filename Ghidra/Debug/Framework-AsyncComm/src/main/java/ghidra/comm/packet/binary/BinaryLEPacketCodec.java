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
package ghidra.comm.packet.binary;

import java.nio.ByteOrder;

/**
 * A codec for encoding packets as binary data into byte arrays in little-endian order
 */
public class BinaryLEPacketCodec extends AbstractBinaryPacketCodec {

	public static final BinaryLEPacketCodec INSTANCE = new BinaryLEPacketCodec();

	/**
	 * Get the singleton instance of this codec
	 * 
	 * @return the instance
	 */
	public static BinaryLEPacketCodec getInstance() {
		return INSTANCE;
	}

	protected BinaryLEPacketCodec() {
	}

	@Override
	protected ByteOrder getDefaultByteOrder() {
		return ByteOrder.LITTLE_ENDIAN;
	}
}
