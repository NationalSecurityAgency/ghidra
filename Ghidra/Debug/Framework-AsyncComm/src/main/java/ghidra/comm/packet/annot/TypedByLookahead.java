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
package ghidra.comm.packet.annot;

import java.lang.annotation.*;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.impl.TypedByLookaheadWrapperFactory;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketFieldValueMismatchException;
import ghidra.comm.packet.fields.ImplementedBy;
import ghidra.comm.packet.fields.PacketField;

/**
 * An annotation that indicates the type of this field is selected by looking ahead
 * 
 * That is, the decoder will attempt to decode from a list of types in order. The first one to
 * succeed without producing a {@link PacketFieldValueMismatchException} is taken as the type. Thus,
 * this annotation is most useful when the listed packet types have a {@code final}
 * {@link PacketField}, preferably as the first field. If a type is attempted and it produces any
 * exception other than {@link PacketFieldValueMismatchException}, the entire decode will fail.
 * Protocols should be designed to avoid looking ahead too far.
 * 
 * Example:
 * 
 * <pre>
 * public class Command extends Packet {
 * 	&#64;PacketField
 * 	&#64;TypedByLookahead({ Put.class, Get.class })
 * 	public Op op;
 * }
 * 
 * public abstract class Op extends Packet {
 * 	// Type placeholder
 * }
 * 
 * public class Put extends Op {
 * 	&#64;PacketField
 * 	public final String method = "PUT";
 * 
 * 	// Additional fields for "PUT" operation
 * }
 * 
 * public class Get extends Op {
 * 	&#64;PacketField
 * 	public final String method = "GET";
 * 
 * 	// Additional fields for "GET" operation
 * }
 * </pre>
 * 
 * Technically, the {@code Op} placeholder class in the example is not required, but it is a useful
 * convention to avoid mistakes later. For the pattern demonstrated, take care to list
 * {@link Packet}s with longer {@code final} {@link String}s first. If there were another command
 * {@code "PU"} listed before {@code "PUT"}, then {@code "PU"} could be selected by mistake for a
 * {@code "PUT"}, possibly resulting in a {@link PacketDecodeException}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(TypedByLookaheadWrapperFactory.class)
public @interface TypedByLookahead {
	/**
	 * An array of subclasses of the declared field type to try decoding, in order of preference
	 * 
	 * @return the array of subclasses
	 */
	Class<? extends Packet>[] value();
}
