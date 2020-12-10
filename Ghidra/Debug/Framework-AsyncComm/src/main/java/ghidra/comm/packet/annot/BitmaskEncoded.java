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

import ghidra.comm.packet.annot.impl.BitmaskEncodedFieldCodecWrapperFactory;
import ghidra.comm.packet.fields.ImplementedBy;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(BitmaskEncodedFieldCodecWrapperFactory.class)
public @interface BitmaskEncoded {
	Class<? extends Number> type() default Long.class;

	@SuppressWarnings("rawtypes")
	Class<? extends Enum> universe() default DefaultUniverse.class;

	public enum DefaultUniverse {
		// A sentinel
	}
}
