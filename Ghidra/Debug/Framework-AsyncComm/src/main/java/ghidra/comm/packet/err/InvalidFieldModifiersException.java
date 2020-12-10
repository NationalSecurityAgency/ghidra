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

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.fields.PacketField;

/**
 * Occurs if a field annotated with {@link PacketField} has incompatible modifiers
 * 
 * Packet fields must be public so that the codec can access them. A static field must also be a
 * final field. There are few occasions for a packet type to contain static data, and a codec should
 * never interact with such data directly. If incompatible modifiers are found, this exception is
 * thrown upon packet registration.
 */
public class InvalidFieldModifiersException extends PacketAnnotationException {
	public InvalidFieldModifiersException(Class<? extends Packet> packet, Field field,
			Annotation annotation, String msg) {
		super(packet, field, annotation, msg);
	}
}
