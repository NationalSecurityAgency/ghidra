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

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.util.TargetDataTypeConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

/**
 * The description of a debugging symbol
 * 
 * @see TargetSymbolNamespace
 */
@DebuggerTargetObjectIface("Symbol")
public interface TargetSymbol extends TargetObject {

	String DATA_TYPE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "data_type";
	String SIZE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "size";
	String NAMESPACE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "namespace";

	/**
	 * Get the type of this symbol
	 * 
	 * @return a future completing with the type
	 */
	@TargetAttributeType(name = DATA_TYPE_ATTRIBUTE_NAME, fixed = true, hidden = true)
	public default TargetDataType getDataType() {
		return getTypedAttributeNowByName(DATA_TYPE_ATTRIBUTE_NAME, TargetDataType.class,
			TargetDataType.UNDEFINED1);
	}

	/**
	 * Get the type of this symbol converted to a Ghidra data type
	 * 
	 * @return a future completing with the type
	 */
	public default CompletableFuture<DataType> getGhidraDataType(
			TargetDataTypeConverter converter) {
		return converter.convertTargetDataType(getDataType()).thenApply(dt -> dt);
	}

	/**
	 * Get the type of this symbol converted to a Ghidra data type
	 * 
	 * <p>
	 * WARNING: Each call to this variant creates a new {@link TargetDataTypeConverter}, and so does
	 * not take full advantage of its internal cache.
	 * 
	 * @see #getGhidraDataType(TargetDataTypeConverter)
	 */
	public default CompletableFuture<DataType> getGhidraDataType(DataTypeManager dtm) {
		return getGhidraDataType(new TargetDataTypeConverter(dtm));
	}

	/**
	 * Get the type of this symbol converted to a Ghidra data type, without using a
	 * {@link DataTypeManager}
	 *
	 * <p>
	 * It is better to use variants with a {@link DataTypeManager} directly, rather than using no
	 * manager and cloning to one later. The former will select types suited to the data
	 * organization of the destination manager. Using no manager and cloning later will use
	 * fixed-size types.
	 * 
	 * @see #getGhidraDataType(DataTypeManager)
	 */
	public default CompletableFuture<DataType> getGhidraDataType() {
		return getGhidraDataType((DataTypeManager) null);
	}

	/**
	 * Determine whether the symbol has a constant value
	 * 
	 * <p>
	 * Constant symbols include but are not limited to C enumeration constants. Otherwise, the
	 * symbol's value refers to an address, which stores a presumably non-constant value.
	 * 
	 * @return true if constant, or false if not or unspecified
	 */
	public default boolean isConstant() {
		return getValue().isConstantAddress();
	}

	/**
	 * Get the value of the symbol
	 * 
	 * <p>
	 * If the symbol is a constant, then the returned address will be in the constant space.
	 * 
	 * @return the address or constant value of the symbol, or {@link Address#NO_ADDRESS} if
	 *         unspecified
	 */
	@Override
	// NB. TargetObject defines this attribute
	public default Address getValue() {
		return getTypedAttributeNowByName(VALUE_ATTRIBUTE_NAME, Address.class, Address.NO_ADDRESS);
	}

	/**
	 * If known, get the size of the symbol in bytes
	 * 
	 * <p>
	 * The size of a symbol is usually not required at runtime, so a user should be grateful if this
	 * is known. If it is not known, or the symbol does not have a size, this method returns 0.
	 * 
	 * @return the size of the symbol, or 0 if unspecified
	 */
	@TargetAttributeType(
		name = SIZE_ATTRIBUTE_NAME,
		fixed = true,
		hidden = true)
	public default long getSize() {
		return getTypedAttributeNowByName(SIZE_ATTRIBUTE_NAME, Long.class, 0L);
	}

	/**
	 * Get the namespace for this symbol.
	 * 
	 * <p>
	 * While it is most common for a symbol to be an immediate child of its namespace, that is not
	 * necessarily the case. This method is a reliable and type-safe means of obtaining that
	 * namespace.
	 * 
	 * @return a reference to the namespace
	 */
	@TargetAttributeType(
		name = NAMESPACE_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	public default TargetSymbolNamespace getNamespace() {
		return getTypedAttributeNowByName(NAMESPACE_ATTRIBUTE_NAME, TargetSymbolNamespace.class,
			null);
	}
}
