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
package ghidra.trace.database.listing;

import java.util.Collection;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.data.DBTraceDataSettingsOperations;
import ghidra.trace.database.symbol.DBTraceReference;
import ghidra.trace.model.listing.TraceCodeManager;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.util.LockHold;

public interface DBTraceDataAdapter extends DBTraceCodeUnitAdapter, TraceData {
	static String[] EMPTY_STRING_ARRAY = new String[] {};

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
	DBTraceDataAdapter getRoot();

	default String getPrimarySymbolOrDynamicName() {
		/** TODO: Use primary symbol or dynamic name as in {@link DataDB#getPathName()} */
		return "DAT_" + getAddressString(false, false);
	}

	@Override
	default int getNumOperands() {
		return 1;
	}

	@Override
	default TraceReference[] getValueReferences() {
		return getOperandReferences(TraceCodeManager.DATA_OP_INDEX);
	}

	@Override
	default void addValueReference(Address refAddr, RefType type) {
		getTrace().getReferenceManager()
				.addMemoryReference(getLifespan(), getAddress(), refAddr,
					type, SourceType.USER_DEFINED, TraceCodeManager.DATA_OP_INDEX);
	}

	@Override
	default void removeValueReference(Address refAddr) {
		DBTraceReference ref = getTrace().getReferenceManager()
				.getReference(getStartSnap(),
					getAddress(), refAddr, TraceCodeManager.DATA_OP_INDEX);
		if (ref == null) {
			return;
		}
		ref.delete();
	}

	DBTraceDataSettingsOperations getSettingsSpace(boolean createIfAbsent);

	@Override
	default void setLong(String name, long value) {
		getSettingsSpace(true).setLong(getLifespan(), getAddress(), name, value);
	}

	@Override
	default Long getLong(String name) {
		DBTraceDataSettingsOperations space = getSettingsSpace(false);
		if (space != null) {
			Long value = space.getLong(getStartSnap(), getAddress(), name);
			if (value != null) {
				return value;
			}
		}
		Settings defaultSettings = getDefaultSettings();
		return defaultSettings == null ? null : defaultSettings.getLong(name);
	}

	@Override
	default void setString(String name, String value) {
		getSettingsSpace(true).setString(getLifespan(), getAddress(), name, value);
	}

	@Override
	default String getString(String name) {
		DBTraceDataSettingsOperations space = getSettingsSpace(false);
		if (space != null) {
			String value = space.getString(getStartSnap(), getAddress(), name);
			if (value != null) {
				return value;
			}
		}
		Settings defaultSettings = getDefaultSettings();
		return defaultSettings == null ? null : defaultSettings.getString(name);

	}

	@Override
	default void setByteArray(String name, byte[] value) {
		getSettingsSpace(true).setBytes(getLifespan(), getAddress(), name, value);
	}

	@Override
	default byte[] getByteArray(String name) {
		DBTraceDataSettingsOperations space = getSettingsSpace(false);
		if (space != null) {
			byte[] value = space.getBytes(getStartSnap(), getAddress(), name);
			if (value != null) {
				return value;
			}
		}
		Settings defaultSettings = getDefaultSettings();
		return defaultSettings == null ? null : defaultSettings.getByteArray(name);
	}

	@Override
	default void setValue(String name, Object value) {
		getSettingsSpace(true).setValue(getLifespan(), getAddress(), name, value);
	}

	@Override
	default Object getValue(String name) {
		DBTraceDataSettingsOperations space = getSettingsSpace(false);
		if (space != null) {
			Object value = space.getValue(getStartSnap(), getAddress(), name);
			if (value != null) {
				return value;
			}
		}
		Settings defaultSettings = getDefaultSettings();
		return defaultSettings == null ? null : defaultSettings.getValue(name);
	}

	@Override
	default void clearSetting(String name) {
		DBTraceDataSettingsOperations space = getSettingsSpace(false);
		if (space == null) {
			return;
		}
		space.clear(getLifespan(), getAddress(), name);
	}

	@Override
	default void clearAllSettings() {
		DBTraceDataSettingsOperations space = getSettingsSpace(false);
		if (space == null) {
			return;
		}
		space.clear(getLifespan(), getAddress(), null);
	}

	@Override
	default String[] getNames() {
		DBTraceDataSettingsOperations space = getSettingsSpace(false);
		if (space == null) {
			return EMPTY_STRING_ARRAY;
		}
		Collection<String> names = space.getSettingNames(getLifespan(), getAddress());
		return names.toArray(new String[names.size()]);
	}

	@Override
	default boolean isEmpty() {
		DBTraceDataSettingsOperations space = getSettingsSpace(false);
		if (space == null) {
			return true;
		}
		return space.isEmpty(getLifespan(), getAddress());
	}

	default <T extends SettingsDefinition> T getSettingsDefinition(
			Class<T> settingsDefinitionClass) {
		DataType dt = getBaseDataType();
		for (SettingsDefinition def : dt.getSettingsDefinitions()) {
			if (settingsDefinitionClass.isAssignableFrom(def.getClass())) {
				return settingsDefinitionClass.cast(def);
			}
		}
		return null;
	}

	default boolean hasMutability(int mutabilityType) {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().readLock())) {
			MutabilitySettingsDefinition def =
				getSettingsDefinition(MutabilitySettingsDefinition.class);
			if (def != null) {
				return def.getChoice(this) == mutabilityType;
			}
			return false;
		}
	}

	@Override
	default boolean isConstant() {
		return hasMutability(MutabilitySettingsDefinition.CONSTANT);
	}

	@Override
	default boolean isVolatile() {
		return hasMutability(MutabilitySettingsDefinition.VOLATILE);
	}

	@Override
	DBTraceDataAdapter getPrimitiveAt(int offset);
}
