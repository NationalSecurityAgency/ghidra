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

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import ghidra.comm.packet.err.PacketEncodeException;

/**
 * An annotation that indicates a field should be encoded to a restricted, even constant, length
 * 
 * This annotation is only meaningful to string-based packet codecs. Note that this affects only the
 * encoding, so user beware lest decoding is affected by the pad. For example, padding to the left
 * with 0 is acceptable for most positive numeric encodings.
 */
@Retention(RUNTIME)
@Target(FIELD)
public @interface SizeRestricted {
	/**
	 * The side to which padding may be applied
	 */
	public enum PadDirection {
		/**
		 * Pad to the left of (before) the encoded value
		 */
		LEFT,
		/**
		 * Do not permit padding; throw a {@link PacketEncodeException} if below the minimum length
		 */
		NONE,
		/**
		 * Pad to the right of (after) the encoded value
		 */
		RIGHT;
	}

	/**
	 * The direction in which padding may be applied, if at all
	 * 
	 * @return the pad direction
	 */
	PadDirection direction() default PadDirection.NONE;

	/**
	 * The character used for padding
	 * 
	 * @return the pad character
	 */
	char pad() default ' ';

	/**
	 * The fixed length of the encoding
	 * 
	 * Sets the minimum and maximum to the same value. If given, then neither {@link #min()} nor
	 * {@link #max()} can also be given.
	 * 
	 * @return the fixed length
	 */
	int value() default Integer.MIN_VALUE;

	/**
	 * The minimum length of the encoding
	 * 
	 * @return the minimum length
	 */
	int min() default 0;

	/**
	 * The maximum length of the encoding
	 * 
	 * @return the maximum length
	 */
	int max() default Integer.MAX_VALUE;
}
