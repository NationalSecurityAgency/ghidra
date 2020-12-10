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

import ghidra.comm.packet.annot.impl.SizedByMethodsWrapperFactory;
import ghidra.comm.packet.fields.ImplementedBy;

/**
 * An annotation that indicates the encoded length of this field is given by methods associated with
 * another field
 * 
 * The annotated field is called the "sized field," and the field associated with the methods is
 * called the "sizing field(s)." Bot of these fields must be declared in the same {@link Packet}.
 * Furthermore, the sizing field must precede the sized field.
 * 
 * Because the sizing field is accessed via methods, the annotation cannot validate the field
 * ordering, unless the correct field name is given to {@link #modifies()}. If the sizing field does
 * not precede the sized field, then the decoder will not be able to determine the correct size of
 * the sized field, because it will not have yet decoded the sizing field. It's possible more than
 * one field is used by the methods. In that case, {@link #modifies()} can be set to either, but all
 * sizing field(s) must precede the sized field or there will be problems.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(SizedByMethodsWrapperFactory.class)
public @interface SizedByMethods {
	/**
	 * The name of the method that gives the length
	 * 
	 * It must be a getter, i.e., take no arguments and return a numeric type.
	 * 
	 * @return the name of the getter method
	 */
	String getter();

	/**
	 * The name of the field related to the length
	 * 
	 * Liars beware, problems may arise that are difficult to diagnose.
	 * 
	 * @return the name of the sizing field
	 */
	String modifies();

	/**
	 * The name of the method used to set the length
	 * 
	 * It must be a setter, i.e, it must take one argument of the same type returned by the
	 * {@link #getter()}, and return {@code void}.
	 * 
	 * @return the name of the setter method
	 */
	String setter();
}
