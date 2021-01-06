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
package ghidra.trace.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.scalar.Scalar;

public interface DataAdapterFromDataType extends Data {

	default String doToString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getMnemonicString());
		String valueRepresentation = getDefaultValueRepresentation();
		if (valueRepresentation != null) {
			builder.append(' ');
			builder.append(valueRepresentation);
		}
		return builder.toString();
	}

	@Override
	default String getMnemonicString() {
		return getDataType().getMnemonic(this);
	}

	@Override
	default Address getAddress(int opIndex) {
		if (opIndex != 0) {
			return null;
		}
		Object obj = getValue();
		if (obj instanceof Address) {
			return (Address) obj;
		}
		return null;
	}

	@Override
	default Scalar getScalar(int opIndex) {
		if (opIndex != 0) {
			return null;
		}
		Object obj = getValue();
		if (obj instanceof Scalar) {
			return (Scalar) obj;
		}
		else if (obj instanceof Address) {
			Address addrObj = (Address) obj;
			long offset = addrObj.getAddressableWordOffset();
			return new Scalar(addrObj.getAddressSpace().getPointerSize() * 8, offset, false);
		}
		return null;
	}

	@Override
	default Object getValue() {
		return getBaseDataType().getValue(this, this, getLength());
	}

	@Override
	default Class<?> getValueClass() {
		DataType base = getBaseDataType();
		if (base == null) {
			return null;
		}
		return base.getValueClass(this);
	}

	@Override
	default boolean hasStringValue() {
		Class<?> valueClass = getValueClass();
		if (valueClass == null) {
			return false;
		}
		return String.class.isAssignableFrom(valueClass);
	}

	@Override
	default boolean isPointer() {
		return getBaseDataType() instanceof Pointer;
	}

	@Override
	default boolean isUnion() {
		return getBaseDataType() instanceof Union;
	}

	@Override
	default boolean isStructure() {
		return getBaseDataType() instanceof Structure;
	}

	@Override
	default boolean isArray() {
		return getBaseDataType() instanceof Array;
	}

	@Override
	default boolean isDynamic() {
		return getBaseDataType() instanceof DynamicDataType;
	}

	@Override
	default String getDefaultValueRepresentation() {
		return getDataType().getRepresentation(this, this, getLength());
	}

	@Override
	default String getDefaultLabelPrefix(DataTypeDisplayOptions options) {
		return getDataType().getDefaultLabelPrefix(this, this, getLength(), options);
	}
}
