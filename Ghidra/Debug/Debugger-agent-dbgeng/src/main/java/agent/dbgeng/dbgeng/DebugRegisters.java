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
package agent.dbgeng.dbgeng;

import java.util.*;

import agent.dbgeng.dbgeng.DebugValue.DebugValueType;
import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;

/**
 * A wrapper for {@code IDebugRegisters} and its newer variants.
 */
public interface DebugRegisters {
	public static enum DebugRegisterSource {
		DEBUG_REGSRC_DEBUGGEE, //
		DEBUG_REGSRC_EXPLICIT, //
		DEBUG_REGSRC_FRAME, //
		;
	}

	public static enum DebugRegisterFlags implements BitmaskUniverse {
		SUB_REGISTER(1 << 0), //
		;

		private DebugRegisterFlags(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static class DebugRegisterDescription {
		public final String name;
		public final int index;
		public final DebugValueType type;
		public final Set<DebugRegisterFlags> flags;
		public final int subregMaster;
		public final int subregLengthBits;
		public final long subregMask;
		public final int subregShift;

		public DebugRegisterDescription(String name, int index, DebugValueType type,
				BitmaskSet<DebugRegisterFlags> flags, int subregMaster, int subregLengthBits,
				long subregMask, int subregShift) {
			this.name = name;
			this.index = index;
			this.type = type;
			this.flags = Collections.unmodifiableSet(flags);
			this.subregMaster = subregMaster;
			this.subregLengthBits = subregLengthBits;
			this.subregMask = subregMask;
			this.subregShift = subregShift;
		}

		@Override
		public String toString() {
			return String.format(
				"<%s: name='%s' index=%d type=%s flags=%s subregMaster=%d subregLengthBits=%d" +
					" subregMask=%x subregShift=%d>",
				getClass().getSimpleName(), name, index, type, flags, subregMaster,
				subregLengthBits, subregMask, subregShift);
		}
	}

	int getNumberRegisters();

	DebugRegisterDescription getDescription(int registerNumber);

	/**
	 * A shortcut to get all register descriptions for the current process.
	 * 
	 * Uses {@link #getNumberRegisters()} and {@link #getDescription(int)} to retrieve all
	 * descriptions for the current process.
	 * 
	 * @return the list of register descriptions
	 */
	default Set<DebugRegisterDescription> getAllDescriptions() {
		Set<DebugRegisterDescription> result = new LinkedHashSet<>();
		int count = getNumberRegisters();
		for (int i = 0; i < count; i++) {
			result.add(getDescription(i));
		}
		return result;
	}

	int getIndexByName(String name);

	/**
	 * A shortcut to get many register indices in one call.
	 * 
	 * Uses {@link #getIndexByName(String)}.
	 * 
	 * @param names the names whose indices to get
	 * @return the indices in respective order to the given names
	 */
	default int[] getIndicesByNames(String... names) {
		int[] indices = new int[names.length];
		for (int i = 0; i < names.length; i++) {
			indices[i] = getIndexByName(names[i]);
		}
		return indices;
	}

	DebugValue getValue(int index);

	Map<Integer, DebugValue> getValues(DebugRegisterSource source, Collection<Integer> indices);

	/**
	 * A shortcut to get a register value by name.
	 * 
	 * Uses {@link #getIndexByName(String)} followed by {@link #getValue(int)}.
	 * 
	 * @param name the name of the register
	 * @return the value
	 */
	default DebugValue getValueByName(String name) {
		int indexByName = getIndexByName(name);
		if (indexByName >= 0) {
			return getValue(indexByName);
		}
		return null;
	}

	void setValue(int index, DebugValue value);

	void setValues(DebugRegisterSource source, Map<Integer, DebugValue> values);

	/**
	 * A shortcut to set a register value by name.
	 * 
	 * Uses {@link #getIndexByName(String)} followed by {@link #setValue(int, DebugValue)}.
	 * 
	 * @param name the name of the register
	 * @param value the desired value
	 */
	default void setValueByName(String name, DebugValue value) {
		setValue(getIndexByName(name), value);
	}
}
