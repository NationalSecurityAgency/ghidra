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

import ghidra.comm.packet.annot.impl.CountedByFieldWrapperFactory;
import ghidra.comm.packet.fields.ImplementedBy;

/**
 * An annotation that indicates the number of elements in this field is given by the value of
 * another
 * 
 * The annotated field is called the "counted field," and the field to which this annotation refers
 * is called the "counting field." Both of these fields must be declared in the same {@link Packet}.
 * Furthermore, the counting field must precede the counted field.
 * 
 * This annotation must be preceded by {@link RepeatedField}.
 * 
 * Example:
 * 
 * <pre>
 * &#64;PacketField
 * public int count;
 * 
 * &#64;PacketField
 * &#64;RepeatedField
 * &#64;CountedByField("count")
 * public List<Integer> list;
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(CountedByFieldWrapperFactory.class)
public @interface CountedByField {
	/**
	 * The name of the field that gives the count
	 * 
	 * @return the name of the counting field
	 */
	String value();
}
