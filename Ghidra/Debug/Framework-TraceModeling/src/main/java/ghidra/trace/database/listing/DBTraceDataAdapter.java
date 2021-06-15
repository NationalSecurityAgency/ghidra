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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.data.DBTraceDataSettingsOperations;
import ghidra.trace.database.symbol.DBTraceReference;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.util.*;
import ghidra.util.LockHold;

public interface DBTraceDataAdapter extends DBTraceCodeUnitAdapter, DataAdapterMinimal,
		DataAdapterFromDataType, DataAdapterFromSettings, TraceData {
	static String[] EMPTY_STRING_ARRAY = new String[] {};

	@Override
	DBTraceDataAdapter getRoot();

	@Override
	default TraceReference[] getValueReferences() {
		return (TraceReference[]) DataAdapterMinimal.super.getValueReferences();
	}

	@Override
	default void addValueReference(Address refAddr, RefType type) {
		getTrace().getReferenceManager()
				.addMemoryReference(getLifespan(), getAddress(), refAddr,
					type, SourceType.USER_DEFINED, DATA_OP_INDEX);
	}

	@Override
	default void removeValueReference(Address refAddr) {
		DBTraceReference ref = getTrace().getReferenceManager()
				.getReference(getStartSnap(),
					getAddress(), refAddr, DATA_OP_INDEX);
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

	@Override
	default <T extends SettingsDefinition> T getSettingsDefinition(
			Class<T> settingsDefinitionClass) {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().readLock())) {
			return DataAdapterFromSettings.super.getSettingsDefinition(settingsDefinitionClass);
		}
	}

	@Override
	default boolean hasMutability(int mutabilityType) {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().readLock())) {
			return DataAdapterFromSettings.super.hasMutability(mutabilityType);
		}
	}

	@Override
	DBTraceDataAdapter getPrimitiveAt(int offset);
}
