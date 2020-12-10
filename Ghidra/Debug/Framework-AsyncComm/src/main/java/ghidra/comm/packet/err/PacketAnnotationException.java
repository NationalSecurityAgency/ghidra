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
 * Occurs when a packet is declared with invalid or erroneous annotations
 */
public class PacketAnnotationException extends PacketFieldDeclarationException {
	private final Annotation annotation;

	public PacketAnnotationException(Class<? extends Packet> packet, Field field,
			Annotation annotation, String msg, Throwable cause) {
		super(packet, field, "Cannot apply " + annotation + ": " + msg, cause);
		this.annotation = annotation;
	}

	public PacketAnnotationException(Class<? extends Packet> packet, Field field,
			Annotation annotation, String msg) {
		this(packet, field, annotation, msg, null);
	}

	public Annotation getAnnotation() {
		return annotation;
	}
}
