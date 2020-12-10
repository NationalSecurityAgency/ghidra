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

/**
 * Occurs when a packet annotation refers to a non-existent method
 * 
 * An annotation may refer to a method by name. The name is verified during packet registration. If
 * the method does not exist, then the name is invalid and this exception is thrown.
 */
public class InvalidMethodNameException extends PacketAnnotationException {
	public InvalidMethodNameException(Class<? extends Packet> packet, Field field,
			Annotation annotation, String msg) {
		super(packet, field, annotation, msg);
	}

	public InvalidMethodNameException(Class<? extends Packet> packet, Field field,
			Annotation annotation, String msg, Throwable cause) {
		super(packet, field, annotation, msg, cause);
	}
}
