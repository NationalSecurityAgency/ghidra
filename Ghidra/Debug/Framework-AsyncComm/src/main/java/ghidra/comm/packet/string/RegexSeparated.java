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

import ghidra.comm.packet.annot.CountedByField;
import ghidra.comm.packet.annot.RepeatedField;

/**
 * An annotation that indicates the elements of a field are separated by a regular expression
 * 
 * This annotation is only meaningful to string-based packet codecs. It must be preceded by
 * {@link RepeatedField}.
 * 
 * Example:
 * 
 * <pre>
 * &#64;PacketField
 * &#64;RepeatedField
 * &#64;RegexSeparated(exp=",", tok=",")
 * public List<Integer> list
 * </pre>
 * 
 * This would encode a list as, e.g., {@code "1,2,3"}. Note that {@code RegexSeparated} is subtly
 * different than {@link RegexTerminated} when applied with {@link RepeatedField}. The former
 * requires a terminator between pairs of consecutive elements, whereas the latter requires a
 * terminator after every element. The difference is in the final element. When encoding of the
 * form, e.g., {@code "a;b;c;"} is required, please refrain from using {@code RegexSeparated}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface RegexSeparated {
	/**
	 * The regular expression to match the tokens separating each encoded element
	 * 
	 * This expression is applied during decoding to determine where each element ends.
	 * 
	 * @see Pattern#compile(String)
	 * @return the separator regular expression
	 */
	String exp();

	/**
	 * True if the separator can be omitted from the final element of an indefinitely-sized list
	 * 
	 * This applies when the {@link CountedByField} annotation is not also present, because the
	 * decoder will not know ahead of time whether or not the current element is the last element.
	 * There is rarely a reason to set this to {@code false}.
	 * 
	 * @return {@code true} to allow omission, {@code false} to forbid omission
	 */
	boolean optional() default true;

	/**
	 * The token to insert between each encoded element
	 * 
	 * This token is inserted during encoding to separate each element. It is validated against
	 * {@link #exp()} to ensure it will match during decode.
	 * 
	 * @return the separator token
	 */
	String tok();
}
