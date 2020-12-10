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
import java.nio.charset.Charset;

import ghidra.comm.packet.PacketCodec;
import ghidra.comm.packet.annot.impl.EncodeCharsWrapperFactory;
import ghidra.comm.packet.fields.ImplementedBy;

/**
 * An annotation to modify the encoding of strings
 * 
 * This annotation transforms a {@link CharSequence} into a byte array. This may have unintended
 * consequences if the {@link PacketCodec} encodes {@link String}s. Most binary codecs will apply a
 * UTF-8 encoding by default, so this annotation provides a way to override that default.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(EncodeCharsWrapperFactory.class)
public @interface EncodeChars {
	/**
	 * The name of the character set encoding to apply
	 * 
	 * @see Charset#forName(String)
	 * @return the name of the character set
	 */
	String value();
}
