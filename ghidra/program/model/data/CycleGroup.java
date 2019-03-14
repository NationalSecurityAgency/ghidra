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
package ghidra.program.model.data;

import java.awt.event.KeyEvent;
import java.util.*;

import javax.swing.KeyStroke;

/**
 * Class to define a set of dataTypes that a single action can cycle through.
 */
public class CycleGroup {
	public static final CycleGroup BYTE_CYCLE_GROUP = new ByteCycleGroup();
	public static final CycleGroup FLOAT_CYCLE_GROUP = new FloatCycleGroup();
	public static final CycleGroup STRING_CYCLE_GROUP = new StringCycleGroup();
	public static final List<CycleGroup> ALL_CYCLE_GROUPS = createCycleGroups();

	private static List<CycleGroup> createCycleGroups() {
		List<CycleGroup> list = new ArrayList<>();
		list.add(BYTE_CYCLE_GROUP);
		list.add(FLOAT_CYCLE_GROUP);
		list.add(STRING_CYCLE_GROUP);
		return Collections.unmodifiableList(list);
	}

	private String name;
	private ArrayList<DataType> dataList;
	protected KeyStroke defaultKeyStroke;

	/**
	 * Constructs a new cycle group with the given dataTypes.
	 * @param name cycle group name which will be the suggested action name
	 * for those plugins which implement a cycle group action.
	 * @param dataTypes data types in the group
	 * @param keyStroke default key stroke for the action to cycle through the
	 * data types
	 */
	public CycleGroup(String name, DataType[] dataTypes, KeyStroke keyStroke) {
		this.name = name;
		this.defaultKeyStroke = keyStroke;
		List<DataType> list = Arrays.asList(dataTypes);
		dataList = new ArrayList<>(list);
	}

	/**
	 * Constructor cycle group with one data type.
	 * @param name cycle group name which will be the suggested action name
	 * for those plugins which implement a cycle group action.
	 * @param dt single data type for the group
	 * @param keyStroke default key stroke for the action to cycle through the
	 * data types
	 */
	public CycleGroup(String name, DataType dt, KeyStroke keyStroke) {
		this(name, new DataType[] { dt }, keyStroke);
	}

	/**
	 * Construct empty group no name, data types or keystroke.
	 */
	public CycleGroup(String name) {
		this(name, new DataType[0], null);
	}

	/**
	 * Get the data types in this group.
	 */
	public DataType[] getDataTypes() {
		DataType[] dt = new DataType[dataList.size()];
		return dataList.toArray(dt);
	}

	/**
	 * @return cycle group name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns number of types in group
	 */
	public int size() {
		return dataList.size();
	}

	public KeyStroke getDefaultKeyStroke() {
		return defaultKeyStroke;
	}

	/**
	 * Add a data type to this group.
	 * @param dt the datatype to be added.
	 */
	public void addDataType(DataType dt) {
		if (dt == null) {
			return;
		}
		if (!exists(dt)) {
			dataList.add(dt);
		}
	}

	/**
	 * Add the data type as the first in the list.
	 * @param dt the dataType to be added.
	 */
	public void addFirst(DataType dt) {
		if (dt == null) {
			return;
		}
		if (!exists(dt)) {
			dataList.add(0, dt);
		}
	}

	/**
	 * Remove the data type from this group.
	 * @param dt the dataType to remove.
	 * 
	 */
	public void removeDataType(DataType dt) {
		dataList.remove(dt);
	}

	/**
	 * Remove first data type in the list.
	 */
	public void removeFirst() {
		dataList.remove(0);
	}

	/**
	 * Remove the last data type in the list.
	 */
	public void removeLast() {
		dataList.remove(dataList.size() - 1);
	}

	/**
	 * Return true if the given data type is in this cycle group.
	 */
	public boolean contains(DataType dt) {
		return exists(dt);
	}

	/**
	 * Return true if the given data type is the same type of any
	 * data types in the list.
	 */
	private boolean exists(DataType dt) {
		for (int i = 0; i < dataList.size(); i++) {
			DataType d = dataList.get(i);
			if (dt.isEquivalent(d)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get next data-type which should be used
	 * @param currentDataType current data type to which this cycle group is to be applied
	 * @param stackPointers if true and currentDataType is a pointer, the pointer's 
	 * base type will be cycled
	 * @return next data-type
	 */
	public DataType getNextDataType(DataType currentDataType, boolean stackPointers) {

		if (dataList.size() == 0) {
			return null;
		}

		DataType dataType = currentDataType;

		Pointer ptr = null;
		if (stackPointers && dataType instanceof Pointer) {
			ptr = (Pointer) dataType;
			dataType = getNextDataType(ptr.getDataType(), true);
			return ptr.newPointer(dataType);
		}

		int index = -1;
		if (dataType != null && !dataType.isEquivalent(DataType.DEFAULT)) {
			for (int i = 0; i < dataList.size(); i++) {
				DataType cycleDt = dataList.get(i);
				if (dataType.isEquivalent(cycleDt)) {
					index = i;
					break;
				}
			}
		}

		if (++index >= dataList.size()) {
			dataType = dataList.get(0);
		}
		else {
			dataType = dataList.get(index);
		}

		return dataType;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class ByteCycleGroup extends CycleGroup {
		public ByteCycleGroup() {
			super("Cycle: byte,word,dword,qword");
			addDataType(new ByteDataType());
			addDataType(new WordDataType());
			addDataType(new DWordDataType());
			addDataType(new QWordDataType());

			defaultKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_B, 0);

		}
	}

	private static class FloatCycleGroup extends CycleGroup {
		public FloatCycleGroup() {
			super("Cycle: float,double");
			addDataType(new FloatDataType());
			addDataType(new DoubleDataType());

			defaultKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_F, 0);
		}
	}

	private static class StringCycleGroup extends CycleGroup {
		public StringCycleGroup() {
			super("Cycle: char,string,unicode");
			addDataType(new CharDataType());
			addDataType(new StringDataType());
			addDataType(new UnicodeDataType());

			defaultKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_QUOTE, 0);
		}
	}
}
