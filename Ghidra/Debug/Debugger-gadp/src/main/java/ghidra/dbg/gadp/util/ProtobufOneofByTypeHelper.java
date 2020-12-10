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
package ghidra.dbg.gadp.util;

import java.util.*;

import com.google.protobuf.*;
import com.google.protobuf.Descriptors.*;

public class ProtobufOneofByTypeHelper<M extends AbstractMessage, B extends Message.Builder> {
	public static OneofDescriptor findOneofByName(Descriptor descriptor, String name) {
		for (OneofDescriptor desc : descriptor.getOneofs()) {
			if (name.equals(desc.getName())) {
				return desc;
			}
		}
		return null;
	}

	public static <M extends AbstractMessage, B extends Message.Builder> ProtobufOneofByTypeHelper<M, B> create(
			M exampleMessage, B exampleBuilder, String oneofName) {
		Descriptor typeDesc = exampleMessage.getDescriptorForType();
		if (exampleBuilder.getDescriptorForType() != typeDesc) {
			throw new IllegalArgumentException(
				"Example message and builder must have the same message type");
		}
		OneofDescriptor oneofDesc = findOneofByName(typeDesc, oneofName);
		if (oneofDesc == null) {
			throw new NoSuchElementException(
				"oneof " + oneofName + " in " + typeDesc);
		}
		return new ProtobufOneofByTypeHelper<>(oneofDesc);
	}

	private final OneofDescriptor descriptor;
	private final Map<Descriptor, FieldDescriptor> fieldsByType;

	private ProtobufOneofByTypeHelper(OneofDescriptor descriptor) {
		this.descriptor = descriptor;
		Map<Descriptor, FieldDescriptor> descsByType = new HashMap<>();
		for (FieldDescriptor desc : descriptor.getFields()) {
			Descriptor type = desc.getMessageType();
			if (type == null || descsByType.put(type, desc) != null) {
				throw new IllegalArgumentException(this.getClass() +
					" requires each fields in " + descriptor + " to be a unique message type");
			}
		}
		this.fieldsByType = Map.copyOf(descsByType);
	}

	public FieldDescriptor getFieldForTypeOf(MessageOrBuilder value) {
		FieldDescriptor field = fieldsByType.get(value.getDescriptorForType());
		if (field == null) {
			throw new IllegalArgumentException(
				"No field in " + descriptor + " has type of " + value);
		}
		return field;
	}

	public void set(B builder, Message value) {
		builder.setField(getFieldForTypeOf(value), value);
	}

	public void set(B builder, Message.Builder value) {
		builder.setField(getFieldForTypeOf(value), value.build());
	}

	@SuppressWarnings("unchecked")
	public <MI extends Message> MI expect(M outer, MI exampleInner) {
		FieldDescriptor field = outer.getOneofFieldDescriptor(descriptor);
		if (field == null || field.getMessageType() != exampleInner.getDescriptorForType()) {
			return null;
		}
		return (MI) outer.getField(field);
	}
}
