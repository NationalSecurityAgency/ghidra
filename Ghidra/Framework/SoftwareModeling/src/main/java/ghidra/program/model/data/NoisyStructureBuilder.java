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

import java.util.Iterator;
import java.util.Map.Entry;
import java.util.TreeMap;

/**
 * Build a structure from a "noisy" source of field information.
 * Feed it field records, either via addDataType(), when we
 * have more definitive info about the size of the field, or via addReference()
 * when we have a pointer reference to the field with possibly less info about the field size.
 * 
 * As records come in, overlaps and conflicts in specific field data-types are resolved.
 * In a conflict, less specific data-types are replaced.
 * After all information is collected a final Structure can be built by iterating over
 * the final field entries.
 */
public class NoisyStructureBuilder {
	private TreeMap<Long, DataType> offsetToDataTypeMap = new TreeMap<>();
	private Structure structDT = null;
	private long sizeOfStruct = 0;

	private void computeMax(long newOff, int length) {
		if (sizeOfStruct < (newOff + length)) {
			sizeOfStruct = newOff + length;
		}
	}

	/**
	 * Check if the given range overlaps any existing field entries.  If it does
	 * return the first entry, otherwise return null.
	 * @param offset is the starting of the range (in bytes)
	 * @param size is the number of bytes in the range
	 * @return the first overlapping entry or null
	 */
	private Entry<Long, DataType> checkForOverlap(long offset, int size) {
		Entry<Long, DataType> res = offsetToDataTypeMap.floorEntry(offset);
		if (res != null) {
			long last = res.getKey().longValue() + res.getValue().getLength();
			if (offset < last) {
				return res;
			}
		}
		res = offsetToDataTypeMap.higherEntry(offset);
		if (res != null) {
			long last = offset + size;
			if (res.getKey() < last) {
				return res;
			}
		}
		return null;
	}

	/**
	 * @return the size of the structure in bytes (given current information)
	 */
	public long getSize() {
		return sizeOfStruct;
	}

	/**
	 * Add data-type information about a specific field
	 * @param offset of the field within the structure
	 * @param dt is the data-type of field if known (null otherwise)
	 */
	public void addDataType(long offset, DataType dt) {
		if (dt == null || dt instanceof VoidDataType) {
			computeMax(offset, 1);
			return;
		}
		if (dt instanceof Pointer) {
			DataType baseType = ((Pointer) dt).getDataType();
			if (baseType != null && baseType.equals(structDT)) {
				// Be careful of taking a pointer to the structure when the structure
				// is not fully defined
				DataTypeManager manager = dt.getDataTypeManager();
				dt = manager.getPointer(DataType.DEFAULT, dt.getLength());
			}
		}
		computeMax(offset, dt.getLength());
		Entry<Long, DataType> firstEntry = checkForOverlap(offset, dt.getLength());
		if (firstEntry != null) {
			if (firstEntry.getKey().longValue() == offset &&
				firstEntry.getValue().getLength() == dt.getLength()) {
				// Matching field,  compare the data-types
				if (dt != MetaDataType.getMostSpecificDataType(firstEntry.getValue(), dt)) {
					return;
				}
			}
			else if (firstEntry.getKey().longValue() <= offset &&
				offset + dt.getLength() < firstEntry.getKey().longValue() +
					firstEntry.getValue().getLength()) {
				// Completely contained within preexisting entry
				if (!(firstEntry.getValue() instanceof Undefined)) {
					// Don't override preexisting entry with a smaller one
					return;
				}
				// unless the preexising entry is undefined
			}
			else if (dt instanceof Undefined) {
				// The new field either fully or partially contains preexisting fields
				return;
			}
			offsetToDataTypeMap.subMap(firstEntry.getKey(), offset + dt.getLength()).clear();	// Clear overlapping entries
		}
		offsetToDataTypeMap.put(Long.valueOf(offset), dt);
	}

	/**
	 * Adds information for a field given a pointer reference.
	 * The data-type information is not used unless it is a pointer.
	 * @param offset is the offset of the field within the structure
	 * @param dt is the data-type of the pointer to the field (or null)
	 */
	public void addReference(long offset, DataType dt) {
		if (dt != null && dt instanceof Pointer) {
			dt = ((Pointer) dt).getDataType();
			if (dt != null && dt.equals(structDT)) {
				return;		// Don't allow structure to contain itself
			}
			if (dt instanceof Structure) {
				if (((Structure) dt).getNumDefinedComponents() == 0) {
					computeMax(offset, 1);
					return;
				}
			}
			addDataType(offset, dt);
		}
		else {
			computeMax(offset, 1);
		}
	}

	/**
	 * We may have partial information about the size of the structure.  This method feeds it to the
	 * builder as a minimum size for the structure.
	 * @param size is the minimum size in bytes
	 */
	public void setMinimumSize(long size) {
		if (size > sizeOfStruct) {
			sizeOfStruct = size;
		}
	}

	/**
	 * @return an iterator to the current field entries
	 */
	public Iterator<Entry<Long, DataType>> iterator() {
		return offsetToDataTypeMap.entrySet().iterator();
	}

	/**
	 * Populate this builder with fields from a preexisting Structure.
	 * The builder presumes it is rebuilding this Structure so it can check for
	 * pathological containment issues.
	 * @param dt is the preexisting Structure
	 */
	public void populateOriginalStructure(Structure dt) {
		structDT = dt;
		DataTypeComponent[] components = structDT.getDefinedComponents();
		for (DataTypeComponent component : components) {
			offsetToDataTypeMap.put((long) component.getOffset(), component.getDataType());
		}
		sizeOfStruct = structDT.getLength();
	}
}
