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
package ghidra.comm.packet.string;

import java.lang.annotation.*;
import java.util.regex.Pattern;

import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.err.PacketDecodeException;

/**
 * An annotation that indicates a field is terminated by a token matching a regular expression
 * 
 * This annotation is only meaningful to string-based packet codecs. When encoded, the annotated
 * field will be conditionally followed by a terminator token. When decoded, the field codec will
 * read ahead, using a regular expression to locate the terminator and limit the chained codec to
 * the preceding data. Once decoded, it will resume immediately following the matched terminator.
 * 
 * Note that when used with {@link RepeatedField}, this annotation requires every element, including
 * the last, to be terminated. To allow the final terminator to be omitted, consider using
 * {@link RegexSeparated}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface RegexTerminated {
	/**
	 * The regular expression to match the terminating token
	 * 
	 * This expression is applied during decode to scan ahead to the terminator.
	 * 
	 * @see Pattern#compile(String)
	 * @return the terminator regular expression
	 */
	String exp();

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

	/**
	 * The token to insert after the field
	 * 
	 * This token is inserted during encoding to terminate the field. It is validated against
	 * {@link #exp()} to ensure it will match during decode.
	 * 
	 * @return the terminator token
	 */
	String tok();
}
