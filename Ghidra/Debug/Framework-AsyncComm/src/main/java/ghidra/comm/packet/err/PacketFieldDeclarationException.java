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

import java.lang.reflect.Field;

import ghidra.comm.packet.Packet;

/**
 * Occurs when the specified annotations are not compatible with the codec
 * 
 * Each annotation usually corresponds to a transformation, which may modify the type of the field
 * during the encode or decode process. Each pair of neighboring transformations must negotiate that
 * type, and the final transformation must negotiate that type with the codec. If this process
 * fails, this exception is thrown upon packet registration.
 */
public class PacketFieldDeclarationException extends PacketDeclarationException {
	private final Field field;

	public PacketFieldDeclarationException(Class<? extends Packet> packet, Field field, String msg,
			Throwable cause) {
		super(packet, "With field " + field.getName() + ": " + msg, cause);
		this.field = field;
	}

	public PacketFieldDeclarationException(Class<? extends Packet> packet, Field field,
			String msg) {
		this(packet, field, msg, null);
	}

	/**
	 * Get the field whose transformation types could not be negotiated
	 * 
	 * @return the field
	 */
	public Field getField() {
		return field;
	}
}
