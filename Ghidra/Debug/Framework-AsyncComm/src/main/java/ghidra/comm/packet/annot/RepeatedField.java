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
import java.util.Collection;

import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.impl.RepeatedFieldWrapperFactory;
import ghidra.comm.packet.fields.ImplementedBy;

/**
 * An annotation applied to collections and arrays
 * 
 * This annotation is required for collections and arrays, and it also provides some information
 * about types for the decoder to use. Each element is encoded in order defined by the collection's
 * iterator.
 * 
 * A packet may declare abstract collection types, but something must determine what concrete type
 * to use. The same is true of its elements. If unspecified, the decoder will use implementations
 * provided by the {@link PacketFactory}. If, for some reason, those are insufficient, the packet
 * can either declare the field as the concrete type -- usually not the desired solution -- or set
 * an attribute on this annotation.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(RepeatedFieldWrapperFactory.class)
public @interface RepeatedField {
	/**
	 * The concrete type to use for the collection
	 * 
	 * @return the class for the collection
	 */
	@SuppressWarnings("rawtypes")
	Class<? extends Collection> container() default DefaultContainer.class;

	/**
	 * The concrete type to use for the elements of the collection or array
	 * 
	 * @return the class for the elements
	 */
	Class<?> elements() default DefaultElements.class;

	/**
	 * A sentinel to represent the default, would-be-null, value for
	 * {@link RepeatedField#container()}
	 */
	interface DefaultContainer extends Collection<Object> {
		// A sentinel
	}

	/**
	 * A sentinel to represent the default, would-be-null, value for
	 * {@link RepeatedField#elements()}
	 */
	interface DefaultElements {
		// A sentinel
	}
}
