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
 * Occurs when a packet annotation refers to a non-existent packet field
 * 
 * Some annotations refer to other fields by name. The name is verified during packet registration.
 * If the field does not exist, or the field is not annotated by {@link PacketField}, then the name
 * is invalid and this exception is thrown.
 */
public class InvalidFieldNameException extends PacketAnnotationException {
	public InvalidFieldNameException(Class<? extends Packet> pktType, Field field,
			Annotation annotation, String msg, Throwable cause) {
		super(pktType, field, annotation, msg, cause);
	}

	public InvalidFieldNameException(Class<? extends Packet> pktType, Field field,
			Annotation annotation, String msg) {
		super(pktType, field, annotation, msg);
	}
}
