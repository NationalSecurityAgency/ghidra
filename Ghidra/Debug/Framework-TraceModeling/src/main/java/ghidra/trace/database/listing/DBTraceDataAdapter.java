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
import ghidra.trace.model.Trace.TraceCodeChangeType;
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
		try (LockHold hold = getTrace().lockRead()) {
			return (TraceReference[]) DataAdapterMinimal.super.getValueReferences();
		}
	}

	@Override
	default void addValueReference(Address refAddr, RefType type) {
		try (LockHold hold = getTrace().lockWrite()) {
			getTrace().getReferenceManager()
					.addMemoryReference(getLifespan(), getAddress(), refAddr,
						type, SourceType.USER_DEFINED, DATA_OP_INDEX);
		}
	}

	@Override
	default void removeValueReference(Address refAddr) {
		try (LockHold hold = getTrace().lockWrite()) {
			DBTraceReference ref = getTrace().getReferenceManager()
					.getReference(getStartSnap(),
						getAddress(), refAddr, DATA_OP_INDEX);
			if (ref == null) {
				return;
			}
			ref.delete();
		}
	}

	DBTraceDataSettingsOperations getSettingsSpace(boolean createIfAbsent);

	@Override
	default void setLong(String name, long value) {
		try (LockHold hold = getTrace().lockWrite()) {
			getSettingsSpace(true).setLong(getLifespan(), getAddress(), name, value);
		}
		getTrace().setChanged(new TraceChangeRecord<>(
			TraceCodeChangeType.DATA_TYPE_SETTINGS_CHANGED, getTraceSpace(), this.getBounds(), null,
			null));
	}

	@Override
	default Long getLong(String name) {
		try (LockHold hold = getTrace().lockRead()) {
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
	}

	@Override
	default void setString(String name, String value) {
		try (LockHold hold = getTrace().lockWrite()) {
			getSettingsSpace(true).setString(getLifespan(), getAddress(), name, value);
		}
		getTrace().setChanged(new TraceChangeRecord<>(
			TraceCodeChangeType.DATA_TYPE_SETTINGS_CHANGED, getTraceSpace(), this.getBounds(), null,
			null));
	}

	@Override
	default String getString(String name) {
		try (LockHold hold = getTrace().lockRead()) {
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

	}

	@Override
	default void setByteArray(String name, byte[] value) {
		try (LockHold hold = getTrace().lockWrite()) {
			getSettingsSpace(true).setBytes(getLifespan(), getAddress(), name, value);
		}
		getTrace().setChanged(new TraceChangeRecord<>(
			TraceCodeChangeType.DATA_TYPE_SETTINGS_CHANGED, getTraceSpace(), this.getBounds(), null,
			null));
	}

	@Override
	default byte[] getByteArray(String name) {
		try (LockHold hold = getTrace().lockRead()) {
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
	}

	@Override
	default void setValue(String name, Object value) {
		try (LockHold hold = getTrace().lockWrite()) {
			getSettingsSpace(true).setValue(getLifespan(), getAddress(), name, value);
		}
		getTrace().setChanged(new TraceChangeRecord<>(
			TraceCodeChangeType.DATA_TYPE_SETTINGS_CHANGED, getTraceSpace(), this.getBounds(), null,
			null));
	}

	@Override
	default Object getValue(String name) {
		try (LockHold hold = getTrace().lockRead()) {
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
	}

	@Override
	default void clearSetting(String name) {
		try (LockHold hold = getTrace().lockWrite()) {
			DBTraceDataSettingsOperations space = getSettingsSpace(false);
			if (space == null) {
				return;
			}
			space.clear(getLifespan(), getAddress(), name);
		}
		getTrace().setChanged(new TraceChangeRecord<>(
			TraceCodeChangeType.DATA_TYPE_SETTINGS_CHANGED, getTraceSpace(), this.getBounds(), null,
			null));
	}

	@Override
	default void clearAllSettings() {
		try (LockHold hold = getTrace().lockWrite()) {
			DBTraceDataSettingsOperations space = getSettingsSpace(false);
			if (space == null) {
				return;
			}
			space.clear(getLifespan(), getAddress(), null);
		}
		getTrace().setChanged(new TraceChangeRecord<>(
			TraceCodeChangeType.DATA_TYPE_SETTINGS_CHANGED, getTraceSpace(), this.getBounds(), null,
			null));
	}

	@Override
	default String[] getNames() {
		try (LockHold hold = getTrace().lockRead()) {
			DBTraceDataSettingsOperations space = getSettingsSpace(false);
			if (space == null) {
				return EMPTY_STRING_ARRAY;
			}
			Collection<String> names = space.getSettingNames(getLifespan(), getAddress());
			return names.toArray(new String[names.size()]);
		}
	}

	@Override
	default boolean isEmpty() {
		try (LockHold hold = getTrace().lockRead()) {
			DBTraceDataSettingsOperations space = getSettingsSpace(false);
			if (space == null) {
				return true;
			}
			return space.isEmpty(getLifespan(), getAddress());
		}
	}

	@Override
	default <T extends SettingsDefinition> T getSettingsDefinition(
			Class<T> settingsDefinitionClass) {
		try (LockHold hold = getTrace().lockRead()) {
			return DataAdapterFromSettings.super.getSettingsDefinition(settingsDefinitionClass);
		}
	}

	@Override
	default boolean hasMutability(int mutabilityType) {
		try (LockHold hold = getTrace().lockRead()) {
			return DataAdapterFromSettings.super.hasMutability(mutabilityType);
		}
	}

	@Override
	DBTraceDataAdapter getPrimitiveAt(int offset);
}
