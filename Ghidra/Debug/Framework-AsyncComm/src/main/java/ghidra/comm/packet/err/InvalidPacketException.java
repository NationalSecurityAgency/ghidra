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
package ghidra.comm.packet.err;

import ghidra.comm.packet.binary.NullTerminated;

/**
 * Occurs during decode when a packet field does not conform to the expected format
 * 
 * For example, when using a text codec and decoding a byte, only digits are valid, and they must
 * specify a number from 0 to 255. Or, when using a binary codec, a field annotated with
 * {@link NullTerminated} requires a null terminator.
 */
public class InvalidPacketException extends PacketDecodeException {
	public InvalidPacketException(String msg, Throwable cause) {
		super(msg, cause);
	}

	public InvalidPacketException(String msg) {
		super(msg);
	}
}
