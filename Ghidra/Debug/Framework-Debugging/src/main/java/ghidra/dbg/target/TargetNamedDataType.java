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
package ghidra.dbg.target;

import java.util.Collection;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.util.TargetDataTypeConverter;

/**
 * A data type that would have a name in Ghidra's data type manager
 * 
 * <ul>
 * <li>{@code enum}</li>
 * <li>Function signature</li>
 * <li>{@code struct}</li>
 * <li>{@code typedef}</li>
 * <li>{@code union}</li>
 * </ul>
 * 
 * <p>
 * Other types, e.g., pointers, arrays, are modeled as attributes.
 * 
 * <p>
 * See {@link TargetDataTypeConverter} to get a grasp of the conventions
 * 
 * @param <T> the type of this object
 */
@DebuggerTargetObjectIface("DataType")
public interface TargetNamedDataType extends TargetObject, TargetDataType {

	enum NamedDataTypeKind {
		ENUM, FUNCTION, STRUCT, TYPEDEF, UNION;
	}

	String NAMED_DATA_TYPE_KIND_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "type_kind";
	String ENUM_BYTE_LENGTH_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "byte_length";
	String NAMESPACE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "namespace";

	String FUNCTION_RETURN_INDEX = "return";
	String FUNCTION_PARAMETER_DIM = "param";

	/**
	 * Get the members of this data type in order.
	 * 
	 * <p>
	 * While it is most common for members to be immediate children of the type, that is not
	 * necessarily the case.
	 * 
	 * @implNote By default, this method collects all successor members ordered by path. Overriding
	 *           that behavior is not yet supported.
	 * @return the members
	 */
	default CompletableFuture<? extends Collection<? extends TargetDataTypeMember>> getMembers() {
		return DebugModelConventions.collectSuccessors(this, TargetDataTypeMember.class);
	}

	/**
	 * Get the namespace for this data type.
	 * 
	 * <p>
	 * While it is most common for a data type to be an immediate child of its namespace, that is
	 * not necessarily the case. This method is a reliable and type-safe means of obtaining that
	 * namespace.
	 * 
	 * @return a reference to the namespace
	 */
	@TargetAttributeType(
		name = NAMESPACE_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	default TargetDataTypeNamespace getNamespace() {
		return getTypedAttributeNowByName(NAMESPACE_ATTRIBUTE_NAME, TargetDataTypeNamespace.class,
			null);
	}

	/**
	 * Get the kind of this data type
	 * 
	 * @return the kind
	 */
	@TargetAttributeType(
		name = NAMED_DATA_TYPE_KIND_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	default NamedDataTypeKind getTypeKind() {
		return getTypedAttributeNowByName(NAMED_DATA_TYPE_KIND_ATTRIBUTE_NAME,
			NamedDataTypeKind.class, null);
	}

	@TargetAttributeType(
		name = ENUM_BYTE_LENGTH_ATTRIBUTE_NAME,
		fixed = true,
		hidden = true)
	default Integer getEnumByteLength() {
		return getTypedAttributeNowByName(ENUM_BYTE_LENGTH_ATTRIBUTE_NAME, Integer.class, null);
	}
}
