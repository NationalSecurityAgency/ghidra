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

import java.lang.annotation.*;

import ghidra.comm.packet.err.PacketDecodeException;

/**
 * An annotation that indicates a field is null terminated
 * 
 * This annotation is only meaningful to byte-based packet codecs. When encoded, the annotated field
 * will be conditionally followed by some number of null bytes. When decoded, the field codec will
 * read ahead to the null terminator and limit the chained codec to the preceding data. Once
 * decoded, it will resume immediately following the null terminator.
 * 
 * @see SequenceTerminated
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface NullTerminated {
	/**
	 * The number of null bytes in the terminator
	 * 
	 * @return the number of bytes
	 */
	int value() default 1;

	/**
	 * The name of the field, preceding this one, upon which the terminator is conditioned
	 * 
	 * If a name is provided, and the named field has a value of {@code null} during encoding, then
	 * the terminator is not appended. Otherwise, the terminator is always applied. If a name is
	 * provided, and the decoder hits the buffer limit while reading ahead to the terminator, the
	 * chained field is permitted to consume up to the same limit. Otherwise, a missing terminator
	 * causes a {@link PacketDecodeException}.
	 * 
	 * The named field must be in the same {@link Packet}.
	 * 
	 * @return the name of the field
	 */
	String cond() default "";
}
