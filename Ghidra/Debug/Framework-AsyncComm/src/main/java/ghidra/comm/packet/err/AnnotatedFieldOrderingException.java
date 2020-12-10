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
 * Occurs when a referenced field follows the referring field
 * 
 * For example, when a length field comes after the field whose length it gives, this exception will
 * be thrown upon packet registration. Consider the packet design:
 * 
 * <pre>
 * +-------//---------+--------------+
 * | data (len bytes) | len (1 byte) |
 * +------------------+--------------+
 * </pre>
 * 
 * This cannot happen, because during decoding, the length must be decoded before decoding the field
 * whose length it gives.
 */
public class AnnotatedFieldOrderingException extends PacketAnnotationException {
	public AnnotatedFieldOrderingException(Class<? extends Packet> packet, Field field,
			Annotation annotation, String msg) {
		super(packet, field, annotation, msg);
	}
}
