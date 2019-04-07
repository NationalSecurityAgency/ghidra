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

import java.util.*;

import ghidra.app.plugin.core.datamgr.archive.SourceArchive;
import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.UniversalID;
import ghidra.util.exception.InvalidInputException;

/**
 * Basic implementation of the structure data type
 */
public class StructureDataType extends CompositeDataTypeImpl implements Structure {
	private final static long serialVersionUID = 1;
	private static Comparator<Object> ordinalComparator = new OrdinalComparator();
	protected static Comparator<Object> offsetComparator = new OffsetComparator();
	protected int structLength;
	protected int numComponents; // excludes optional flexible array component
	protected List<DataTypeComponentImpl> components;
	private DataTypeComponentImpl flexibleArrayComponent;

	/**
	 * Construct a new structure with the given name and number of undefined bytes
	 * @param name the name of the new structure
	 * @param length the initial size of the structure
	 */
	public StructureDataType(String name, int length) {
		this(CategoryPath.ROOT, name, length);
	}

	public StructureDataType(String name, int length, DataTypeManager dtm) {
		this(CategoryPath.ROOT, name, length, dtm);
	}

	/**
	 * Construct a new structure with the given name and number of undefined bytes
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure
	 */
	public StructureDataType(CategoryPath path, String name, int length) {
		this(path, name, length, null);
	}

	public StructureDataType(CategoryPath path, String name, int length, DataTypeManager dtm) {
		super(path, name, dtm);
		if (length < 0) {
			throw new IllegalArgumentException("Length can't be negative");
		}

		components = new ArrayList<>();
		structLength = length;
		numComponents = length;
	}

	/**
	 * Construct a new structure with the given name and number of undefined bytes
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure
	 * @param dataTypeManager the data type manager associated with this data type. This can be null. 
	 * Also, the data type manager may not contain this actual data type.
	 */
	public StructureDataType(CategoryPath path, String name, int length, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dtm) {
		super(path, name, universalID, sourceArchive, lastChangeTime, lastChangeTimeInSourceArchive,
			dtm);
		components = new ArrayList<>();
		structLength = length;
		numComponents = length;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (isNotYetDefined()) {
			return "<Empty-Structure>";
		}
		return "";
	}

	@Override
	public boolean isNotYetDefined() {
		return structLength == 0 && flexibleArrayComponent == null;
	}

	@Override
	public DataTypeComponent getComponentAt(int offset) {
		if (offset >= structLength || offset < 0) {
			return null;
		}
		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);
		if (index >= 0) {
			return components.get(index);
		}
		else if (isInternallyAligned()) {
			return null;
		}
		index = -index - 1;
		int ordinal = offset;
		if (index > 0) {
			DataTypeComponent dtc = components.get(index - 1);
			ordinal = dtc.getOrdinal() + offset - dtc.getEndOffset();
		}
		return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
	}

	@Override
	public DataTypeComponent getDataTypeAt(int offset) {
		DataTypeComponent dtc = getComponentAt(offset);
		if (dtc != null) {
			DataType dt = dtc.getDataType();
			if (dt instanceof Structure) {
				return ((Structure) dt).getDataTypeAt(offset - dtc.getOffset());
			}
		}
		return dtc;
	}

	@Override
	public int getLength() {
		if (structLength == 0) {
			return 1; // lie about our length if not yet defined
		}
		return structLength;
	}

	@Override
	public void delete(int index) {
		if (index < 0 || index >= numComponents) {
			throw new ArrayIndexOutOfBoundsException(index);
		}
		int idx = Collections.binarySearch(components, new Integer(index), ordinalComparator);
		if (idx >= 0) {
			DataTypeComponent dtc = components.remove(idx);
			shiftOffsets(idx, -1, -dtc.getLength());
			return;
		}
		idx = -idx - 1;
		shiftOffsets(idx, -1, -1);
		adjustInternalAlignment();
		notifySizeChanged();
	}

	@Override
	public void delete(int[] ordinals) {
		for (int ordinal : ordinals) {
			delete(ordinal);
		}
	}

	private void shiftOffsets(int index, int deltaOrdinal, int deltaOffset) {
		for (int i = index; i < components.size(); i++) {
			DataTypeComponentImpl dtc = components.get(i);
			shiftOffsets(dtc, deltaOrdinal, deltaOffset);
		}
		structLength += deltaOffset;
		numComponents += deltaOrdinal;
	}

	protected void shiftOffsets(DataTypeComponentImpl dtc, int deltaOrdinal, int deltaOffset) {
		dtc.setOffset(dtc.getOffset() + deltaOffset);
		dtc.setOrdinal(dtc.getOrdinal() + deltaOrdinal);
	}

	@Override
	public DataTypeComponent getComponent(int index) {
		if (index == numComponents && flexibleArrayComponent != null) {
			return flexibleArrayComponent;
		}
		if (index < 0 || index >= numComponents) {
			throw new ArrayIndexOutOfBoundsException(index);
		}
		int idx = Collections.binarySearch(components, new Integer(index), ordinalComparator);
		if (idx >= 0) {
			return components.get(idx);
		}
		int offset = 0;
		idx = -idx - 1;
		if (idx == 0) {
			offset = index;
		}
		else {
			DataTypeComponent dtc = components.get(idx - 1);
			offset = dtc.getEndOffset() + index - dtc.getOrdinal();
		}

		return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, index, offset);
	}

	@Override
	public int getNumComponents() {
		return numComponents;
	}

	@Override
	public int getNumDefinedComponents() {
		return components.size();
	}

	@Override
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length,
			String componentName, String comment) {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		validateDataType(dataType);
		if (offset > structLength) {
			numComponents = numComponents + (offset - structLength);
			structLength = offset;
		}
		checkAncestry(dataType);

		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);

		int additionalShift = 0;
		if (index >= 0) {
			DataTypeComponent dtc = components.get(index);
			additionalShift = offset - dtc.getOffset();
		}
		else {
			index = -index - 1;
		}

		int ordinal = offset;
		if (index > 0) {
			DataTypeComponent dtc = components.get(index - 1);
			ordinal = dtc.getOrdinal() + offset - dtc.getEndOffset();
		}

		if (dataType == DataType.DEFAULT) {
			shiftOffsets(index, 1 + additionalShift, 1 + additionalShift);
			return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
		}

		dataType = dataType.clone(getDataTypeManager());

		// TODO Is this the right place to adjust the length?
		int dtLength = dataType.getLength();
		if (dtLength > 0 && dtLength < length) {
			length = dtLength;
		}

		DataTypeComponentImpl dtc = new DataTypeComponentImpl(dataType, this, length, ordinal,
			offset, componentName, comment);
		dataType.addParent(this);
		shiftOffsets(index, 1 + additionalShift, dtc.getLength() + additionalShift);
		components.add(index, dtc);
		adjustInternalAlignment();
		notifySizeChanged();
		return dtc;
	}

	@Override
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length) {
		return insertAtOffset(offset, dataType, length, null, null);
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String componentName,
			String comment) {
		if (length < 1) {
			throw new IllegalArgumentException("Length of " + componentName + ": '" + dataType +
				"' in structure '" + this.name + "' must be >= 1!");
		}
		return doAdd(dataType, length, componentName, comment, true, true);
	}

	public void add(DataType dataType, int length, String componentName, String comment,
			int numCopies) {
		if (length < 1) {
			throw new IllegalArgumentException("Length of " + componentName + ": '" + dataType +
				"' in structure '" + this.name + "' must be >= 1!");
		}
		for (int ii = 0; ii < numCopies; ++ii) {
			doAdd(dataType, length, componentName, comment, false, false);
		}
		adjustInternalAlignment();
		notifySizeChanged();
	}

	private DataTypeComponent doAdd(DataType dataType, int length, String componentName,
			String comment, boolean notify, boolean align) {
		validateDataType(dataType);
		checkAncestry(dataType);

		DataTypeComponentImpl dtc;
		boolean isFlexibleArray = false;
		if (dataType == DataType.DEFAULT) {
			dtc = new DataTypeComponentImpl(DataType.DEFAULT, this, 1, numComponents, structLength);
		}
		else {
			int offset = structLength;
			int ordinal = numComponents;
			isFlexibleArray = (length == 0);
			if (length == 0) {
				// assume trailing flexible array component
				offset = -1;
				ordinal = -1;
				isFlexibleArray = true;
				clearFlexibleArrayComponent();
			}
			dataType = dataType.clone(getDataTypeManager());
			dtc = new DataTypeComponentImpl(dataType, this, length, ordinal, offset, componentName,
				comment);
			dataType.addParent(this);
			if (isFlexibleArray) {
				flexibleArrayComponent = dtc;
			}
			else {
				components.add(dtc);
			}
		}
		if (!isFlexibleArray) {
			numComponents++;
			structLength += dtc.getLength();
		}
		if (align) {
			adjustInternalAlignment();
		}
		if (notify) {
			notifySizeChanged();
		}
		return dtc;
	}

	@Override
	public void growStructure(int amount) {
		numComponents += amount;
		structLength += amount;
		adjustInternalAlignment();
		notifySizeChanged();
	}

	@Override
	public DataTypeComponent insert(int index, DataType dataType, int length, String componentName,
			String comment) {
		if (index < 0 || index > numComponents) {
			throw new ArrayIndexOutOfBoundsException(index);
		}
		if (index == numComponents) {
			return add(dataType, length, componentName, comment);
		}
		validateDataType(dataType);
		checkAncestry(dataType);

		int idx = Collections.binarySearch(components, new Integer(index), ordinalComparator);
		if (idx < 0) {
			idx = -idx - 1;
		}
		if (dataType == DataType.DEFAULT) {
			shiftOffsets(idx, 1, 1);
			return getComponent(index);
		}

		dataType = dataType.clone(getDataTypeManager());

		// TODO Is this the right place to adjust the length?
		int dtLength = dataType.getLength();
		if (dtLength > 0 && dtLength < length) {
			length = dtLength;
		}

		int offset = (getComponent(index)).getOffset();
		DataTypeComponentImpl dtc = new DataTypeComponentImpl(dataType, this, length, index, offset,
			componentName, comment);
		dataType.addParent(this);
		shiftOffsets(idx, 1, dtc.getLength());
		components.add(idx, dtc);
		adjustInternalAlignment();
		notifySizeChanged();
		return dtc;
	}

	@Override
	public void insert(int ordinal, DataType dataType, int length, String name, String comment,
			int numCopies) {
		if (ordinal < 0 || ordinal > numComponents) {
			throw new ArrayIndexOutOfBoundsException(ordinal);
		}
		if (ordinal == numComponents) {
			add(dataType, length, name, comment, numCopies);
			return;
		}
		for (int ii = 0; ii < numCopies; ++ii) {
			insert(ordinal + ii, dataType, length, name, comment);
		}
	}

	@Override
	public void deleteAtOffset(int offset) {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);
		int delta = -1;
		if (index < 0) {
			index = -index - 1;
		}
		else {
			DataTypeComponent dtc = components.remove(index);
			dtc.getDataType().removeParent(this);
			delta = -dtc.getLength();
		}
		shiftOffsets(index, -1, delta);
		adjustInternalAlignment();
		notifySizeChanged();
		return;
	}

	@Override
	public boolean isEquivalent(DataType dataType) {
		if (dataType == this) {
			return true;
		}
		if (dataType == null) {
			return false;
		}

		if (dataType instanceof Structure) {
			Structure struct = (Structure) dataType;
			if (isInternallyAligned() != struct.isInternallyAligned() ||
				isDefaultAligned() != struct.isDefaultAligned() ||
				isMachineAligned() != struct.isMachineAligned() ||
				getMinimumAlignment() != struct.getMinimumAlignment() ||
				getPackingValue() != struct.getPackingValue() ||
				(!isInternallyAligned() && (getLength() != struct.getLength()))) {
				return false;
			}

			DataTypeComponent myFlexComp = getFlexibleArrayComponent();
			DataTypeComponent otherFlexComp = struct.getFlexibleArrayComponent();
			if (myFlexComp != null) {
				if (otherFlexComp == null || !myFlexComp.isEquivalent(otherFlexComp)) {
					return false;
				}
			}
			else if (otherFlexComp != null) {
				return false;
			}

			int myNumComps = getNumComponents();
			int otherNumComps = struct.getNumComponents();
			if (myNumComps != otherNumComps) {
				return false;
			}
			for (int i = 0; i < myNumComps; i++) {
				DataTypeComponent myDtc = getComponent(i);
				DataTypeComponent otherDtc = struct.getComponent(i);

				if (!myDtc.isEquivalent(otherDtc)) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		// TODO FIXME
		int n = components.size();
		boolean didChange = false;
		for (int i = 0; i < n; i++) {
			DataTypeComponentImpl dtc = components.get(i);
			if (dtc.getDataType() == dt) {
				int dtLen = dt.getLength();
				int dtcLen = dtc.getLength();
				if (dtLen < dtcLen) {
					dtc.setLength(dtLen);
					shiftOffsets(i + 1, dtcLen - dtLen, 0);
					didChange = true;
				}
				else if (dtLen > dtcLen) {
					int consumed = consumeBytesAfter(i, dtLen - dtcLen);
					if (consumed > 0) {
						shiftOffsets(i + 1, 0 - consumed, 0);
						didChange = true;
					}
				}
			}
		}
		adjustInternalAlignment();
		if (didChange) {
			notifySizeChanged();
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		adjustInternalAlignment();
		// TODO FIXME
//			checkDeleted();
//			if (!isShowingUndefinedBytes()) {
//				adjustPacking(getDataOrganization(), false, true);
//				return;
//			}
//			int n = components.size();
//			boolean didChange = false;
//			for(int i=0;i<n;i++) {
//				DataTypeComponentDB dtc = components.get(i);
//				if (dtc.getDataType() == dt) {
//					int dtLen = dt.getLength();
//					int dtcLen = dtc.getLength();
//					if (dtLen < dtcLen) {
//						dtc.setLength(dtLen);
//						dtc.updateRecord();
//						shiftOffsets(i+1, dtcLen-dtLen, 0);
//						didChange = true;
//					}
//					else if (dtLen > dtcLen) {
//						int consumed = consumeBytesAfter(i, dtLen-dtcLen);
//						if (consumed > 0) {
//							dtc.updateRecord();
//							shiftOffsets(i+1, -consumed, 0);
//							didChange = true;
//						}
//					}
//				}
//			}
//			if (didChange) {
//				notifySizeChanged();
//			}
	}

	/**
	 * 
	 * @param index the index of the defined component that is consuming the bytes.
	 * @param numBytes the number of undefined bytes to consume
	 * @return the number of bytes actually consumed
	 */

	private int consumeBytesAfter(int definedComponentIndex, int numBytes) {
		DataTypeComponentImpl thisDtc = components.get(definedComponentIndex);
		int thisLen = thisDtc.getLength();
		int nextOffset = thisDtc.getOffset() + thisLen;
		int available;
		// handle last component differently - allow it to grow the structure if needed
		if (definedComponentIndex == components.size() - 1) {
			available = structLength - nextOffset;
			if (numBytes > available) {
				doGrowStructure(numBytes - available);
				available = numBytes;
			}
		}
		else {
			DataTypeComponent nextDtc = components.get(definedComponentIndex + 1);
			available = nextDtc.getOffset() - nextOffset;
		}

		if (numBytes <= available) {
			thisDtc.setLength(thisLen + numBytes);
			return numBytes;
		}
		thisDtc.setLength(thisLen + available);
		return available;
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		StructureDataType struct = new StructureDataType(categoryPath, getName(), getLength(), dtm);
		struct.setDescription(getDescription());
		struct.replaceWith(this);
		return struct;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (getDataTypeManager() == dtm) {
			return this;
		}
		StructureDataType struct =
			new StructureDataType(categoryPath, getName(), getLength(), getUniversalID(),
				getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		struct.setDescription(getDescription());
		struct.replaceWith(this);
		return struct;

	}

	@Override
	public void clearComponent(int index) {
		if (index < 0 || index >= numComponents) {
			throw new ArrayIndexOutOfBoundsException(index);
		}
		int idx = Collections.binarySearch(components, new Integer(index), ordinalComparator);
		if (idx >= 0) {
			DataTypeComponent dtc = components.remove(idx);
			dtc.getDataType().removeParent(this);
			int len = dtc.getLength();
			if (len > 1) {
				shiftOffsets(idx, len - 1, 0);
			}
		}
		adjustInternalAlignment();
	}

	/**
	 * Replaces the internal components of this structure with components of the
	 * given structure. 
	 * @param dataType the structure to get the component information from.
	 * @throws IllegalArgumentException if any of the component data types 
	 * are not allowed to replace a component in this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.
	 * @see ghidra.program.database.data.DataTypeDB#replaceWith(ghidra.program.model.data.DataType)
	 */
	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Structure)) {
			throw new IllegalArgumentException();
		}
		int oldLength = structLength;
		doReplaceWith((Structure) dataType);
		if (oldLength != structLength) {
			notifySizeChanged();
		}
	}

	private void doReplaceWith(Structure struct) {
		components.clear();
		flexibleArrayComponent = null;
		if (struct.isNotYetDefined()) {
			structLength = 0;
			numComponents = 0;
		}
		else {
			structLength = struct.getLength();
			numComponents = structLength;
		}
		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];
			DataType dt = dtc.getDataType();
			replaceAtOffset(dtc.getOffset(), dt, dtc.getLength(), dtc.getFieldName(),
				dtc.getComment());
		}
		// ok now that all components have been laid down, see if we can make any of them bigger
		// without affecting any offsets
		for (int i = 0; i < components.size(); i++) {
			DataTypeComponent dtc = components.get(i);
			DataType dataType = dtc.getDataType();
			if (dataType.getLength() > dtc.getLength()) {
				int n = consumeBytesAfter(i, dataType.getLength() - dtc.getLength());
				if (n > 0) {
					shiftOffsets(i + 1, 0 - n, 0);
				}
			}
		}
		DataTypeComponent flexComponent = struct.getFlexibleArrayComponent();
		if (flexComponent != null) {
			setFlexibleArrayComponent(flexComponent.getDataType(), flexComponent.getFieldName(),
				flexComponent.getComment());
		}
		setDataAlignmentInfo(struct);
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		int n = components.size();
		for (int i = n - 1; i >= 0; i--) {
			DataTypeComponentImpl dtc = components.get(i);
			if (dtc.getDataType() == dt) {
				dt.removeParent(this);
				components.remove(i);
				shiftOffsets(i, dtc.getLength() - 1, 0);
			}
		}
		adjustInternalAlignment();
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		try {
			validateDataType(newDt);
			checkAncestry(newDt);
		}
		catch (Exception e) {
			newDt = DataType.DEFAULT;
		}

		boolean changed = false;
		int nextIndex = 0; // index of next defined component.
		Iterator<DataTypeComponentImpl> it = components.iterator();
		while (it.hasNext()) {
			nextIndex++;
			DataTypeComponentImpl comp = it.next();
			DataType compDt = comp.getDataType();
			if (oldDt == compDt) {
				oldDt.removeParent(this);
				comp.setDataType(newDt);
				newDt.addParent(this);
				int len = newDt.getLength();
				int oldLen = comp.getLength();
				if (len > 0) {
					if (len < oldLen) {
						comp.setLength(len);
						shiftOffsets(nextIndex, oldLen - len, 0);
					}
					else if (len > oldLen) {
						int bytesAvailable = getNumUndefinedBytes(comp.getOrdinal() + 1);
						int bytesNeeded = len - oldLen;
						if (bytesNeeded <= bytesAvailable) {
							comp.setLength(len);
							shiftOffsets(nextIndex, -bytesNeeded, 0);
						}
						else if (comp.getOrdinal() == getLastDefinedComponentIndex()) { // we are the last defined component, grow structure
							doGrowStructure(bytesNeeded - bytesAvailable);
							comp.setLength(len);
							shiftOffsets(nextIndex, -bytesNeeded, 0);
						}
						else {
							comp.setLength(oldLen + bytesAvailable);
							shiftOffsets(nextIndex, -bytesAvailable, 0);
						}
					}
				}
				changed = true;
			}
		}

		adjustInternalAlignment();
		if (changed) {
			notifySizeChanged();
		}
	}

	@Override
	public DataTypeComponent[] getDefinedComponents() {
		return components.toArray(new DataTypeComponent[components.size()]);
	}

	@Override
	public DataTypeComponent[] getComponents() {
		DataTypeComponent[] comps = new DataTypeComponent[numComponents];
		for (int i = 0; i < comps.length; i++) {
			comps[i] = getComponent(i);
		}
		return comps;
	}

	@Override
	public DataTypeComponent replace(int index, DataType dataType, int length, String componentName,
			String comment) {
		if (index < 0 || index >= numComponents) {
			throw new ArrayIndexOutOfBoundsException(index);
		}
		validateDataType(dataType);
		checkAncestry(dataType);
		dataType = dataType.clone(getDataTypeManager());

		DataTypeComponentImpl origDtc = (DataTypeComponentImpl) getComponent(index);
		DataTypeComponent replacement = replace(origDtc, dataType, length, componentName, comment);
		adjustInternalAlignment();
		return replacement;
	}

	@Override
	public DataTypeComponent replace(int index, DataType dataType, int length) {
		return replace(index, dataType, length, null, null);
	}

	@Override
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length,
			String componentName, String comment) {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		if (offset >= structLength) {
			throw new IllegalArgumentException(
				"Offset " + offset + " is beyond end of structure (" + structLength + ").");
		}
		validateDataType(dataType);
		checkAncestry(dataType);
		dataType = dataType.clone(getDataTypeManager());
		DataTypeComponentImpl origDtc = (DataTypeComponentImpl) getComponentAt(offset);
		DataTypeComponent replacement = replace(origDtc, dataType, length, componentName, comment);
		adjustInternalAlignment();
		return replacement;
	}

	/**
	 * Replace the indicated component with a new component containing the 
	 * specified data type.
	 * @param origDtc the original data type component in this structure.
	 * @param dataType the data type of the new component
	 * @param length the length of the new component
	 * @param componentName the field name of the new component
	 * @param comment the commewnt for the new component
	 * @return the new component or null if the new component couldn't fit.
	 * @throws IllegalArgumentException if the dataType.getLength() is positive 
	 * and does not match the given length parameter.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to replace a component in this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.
	 */
	private DataTypeComponent replace(DataTypeComponentImpl origDtc, DataType dataType, int length,
			String componentName, String comment) {

		int ordinal = origDtc.getOrdinal();
		int newOffset = origDtc.getOffset();
		int dtcLength = origDtc.getLength();

		// TODO Is this the right place to adjust the length?
		int dtLength = dataType.getLength();
		if (dtLength > 0 && dtLength < length) {
			length = dtLength;
		}

		origDtc.getDataType().removeParent(this);
		DataTypeComponentImpl newDtc = new DataTypeComponentImpl(dataType, this, length, ordinal,
			newOffset, componentName, comment);
		dataType.addParent(this);
		int bytesNeeded = length - dtcLength;
		int deltaOrdinal = -bytesNeeded;
		if (bytesNeeded > 0) {
			int bytesAvailable = getNumUndefinedBytes(ordinal + 1);
			if (bytesAvailable < bytesNeeded) {
				if (ordinal == getLastDefinedComponentIndex()) {
					growStructure(bytesNeeded - bytesAvailable);
				}
				else {
					throw new IllegalArgumentException("Not enough undefined bytes to fit " +
						dataType.getPathName() + " in structure " + getPathName() +
						" at offset 0x" + Integer.toHexString(newOffset) + "." + " It needs " +
						(bytesNeeded - bytesAvailable) + " more byte(s) to be able to fit.");
				}
			}
		}
		int index = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
		if (index < 0) {
			index = -index - 1;
		}
		else {
			components.remove(index);
		}
		components.add(index, newDtc);
		if (deltaOrdinal != 0) {
			shiftOffsets(index + 1, deltaOrdinal, 0);
		}
		return newDtc;
	}

	private int getLastDefinedComponentIndex() {
		if (components.size() == 0) {
			return 0;
		}
		DataTypeComponent dataTypeComponent = components.get(components.size() - 1);
		return dataTypeComponent.getOrdinal();
	}

	/**
	 * Gets the number of Undefined bytes beginning at the indicated component 
	 * index. Undefined bytes that have a field name or comment specified are 
	 * also included.
	 * @param index the component index to begin checking at.
	 * @return the number of contiguous undefined bytes
	 */
	protected int getNumUndefinedBytes(int index) {
		if (index >= numComponents) {
			return 0;
		}
		int idx = Collections.binarySearch(components, new Integer(index), ordinalComparator);
		DataTypeComponent dtc = null;
		if (idx < 0) {
			idx = -idx - 1;
			if (idx >= components.size()) {
				return numComponents - index;
			}
			dtc = components.get(idx);
			return dtc.getOrdinal() - index;
		}
		return 0;

	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
	}

	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}

	@Override
	public void deleteAll() {
		for (int i = 0; i < components.size(); i++) {
			DataTypeComponent dtc = components.get(i);
			dtc.getDataType().removeParent(this);
		}
		components.clear();
		structLength = 0;
		numComponents = 0;
		flexibleArrayComponent = null;
		adjustInternalAlignment();
		notifySizeChanged();
	}

	@Override
	public String getDefaultLabelPrefix() {
		return getName();
	}

	@Override
	public void realign() {
		adjustInternalAlignment();
	}

	@Override
	public void pack(int packingSize) throws InvalidInputException {
		setPackingValue(packingSize);
	}

	/**
	 * Adjust the alignment, packing and padding of components within this structure based upon the 
	 * current alignment and packing attributes for this structure. This method should be 
	 * called to basically fix up the layout of the internal components of the structure 
	 * after other code has changed the attributes of the structure.
	 * <BR>When switching between internally aligned and unaligned this method corrects the 
	 * component ordinal numbering also.
	 * @return true if the structure was changed by this method.
	 */
	protected boolean adjustComponents() {
		boolean internallyAligned = isInternallyAligned();
		boolean keepDefinedDefaults = !internallyAligned;

		int oldLength = structLength;

		if (!isInternallyAligned()) {
			boolean changed = adjustUnalignedComponents();
			if (changed) {
				if (oldLength != structLength) {
					notifySizeChanged();
				}
			}
			return changed;
		}

		boolean compositeDBChanged = false;
		boolean componentsDBChanged = false;
		int packingAlignment = getPackingValue();

		// Adjust each of the components.
		int currentOrdinal = 0;
		int currentOffset = 0;
		int allComponentsLCM = 1;
		for (DataTypeComponentImpl dataTypeComponent : components) {

			DataType componentDt = dataTypeComponent.getDataType();
			if (!keepDefinedDefaults && DataType.DEFAULT == componentDt) {
				continue; // Discard a defined Default data type.
			}
			int componentLength = dataTypeComponent.getLength();
			int componentOrdinal = dataTypeComponent.getOrdinal();
			int componentOffset = dataTypeComponent.getOffset();
			int dtLength = componentDt.getLength();
			if (dtLength <= 0) {
				dtLength = componentLength;
			}

			int componentAlignment = getPackedAlignment(componentDt, dtLength, packingAlignment);

			allComponentsLCM =
				DataOrganizationImpl.getLeastCommonMultiple(allComponentsLCM, componentAlignment);

			int newOffset = DataOrganizationImpl.getOffset(componentAlignment, currentOffset);
			currentOffset = newOffset + dtLength;
			if (componentOrdinal == currentOrdinal && componentOffset == newOffset &&
				componentLength == dtLength) {
				currentOrdinal++;
				continue; // No change needed.
			}
			dataTypeComponent.setOffset(newOffset);
			dataTypeComponent.setOrdinal(currentOrdinal);
			dataTypeComponent.setLength(dtLength);
			currentOrdinal++;
			componentsDBChanged = true;
		}

		if (flexibleArrayComponent != null) {
			// account for flexible array type in any end of structure padding
			DataType dataType = flexibleArrayComponent.getDataType();
			int componentAlignment =
				getPackedAlignment(dataType, dataType.getLength(), packingAlignment);
			currentOffset = DataOrganizationImpl.getOffset(componentAlignment, currentOffset);
			allComponentsLCM =
				DataOrganizationImpl.getLeastCommonMultiple(allComponentsLCM, componentAlignment);
		}

		// Adjust the structure
		compositeDBChanged = updateComposite(currentOrdinal, currentOffset);

		boolean addedPadding = alignEndOfStruct(allComponentsLCM);

		if (componentsDBChanged || compositeDBChanged || addedPadding) {
			if (oldLength != structLength) {
				notifySizeChanged();
			}
			return true;
		}
		return false;
	}

	private int getPackedAlignment(DataType componentDt, int dtLength, int packingAlignment) {
		DataOrganization dataOrganization = getDataOrganization();
		int componentAlignment = dataOrganization.getAlignment(componentDt, dtLength);
		int componentForcedAlignment = dataOrganization.getForcedAlignment(componentDt);
		boolean componentForcingAlignment = componentForcedAlignment > 0;
		if (componentForcingAlignment) {
			componentAlignment = DataOrganizationImpl.getLeastCommonMultiple(componentAlignment,
				componentForcedAlignment);
		}
		if (packingAlignment > 0) {
			if (componentForcedAlignment > packingAlignment) {
				componentAlignment = componentForcedAlignment;
			}
			else if (componentAlignment > packingAlignment) {
				componentAlignment = packingAlignment;
			}
		}
		return componentAlignment;
	}

	private boolean adjustUnalignedComponents() {
		boolean changed = false;
		int currentOrdinal = 0;
		int componentCount = 0;
		int currentOffset = 0;
		for (DataTypeComponentImpl dataTypeComponent : components) {
			int componentLength = dataTypeComponent.getLength();
			int componentOffset = dataTypeComponent.getOffset();
			int numUndefinedsBefore = componentOffset - currentOffset;
			componentCount += numUndefinedsBefore;
			currentOffset += numUndefinedsBefore;
			currentOrdinal += numUndefinedsBefore;
			componentCount++;
			currentOffset += componentLength;
			if (dataTypeComponent.getOrdinal() != currentOrdinal) {
				dataTypeComponent.setOrdinal(currentOrdinal);
				changed = true;
			}
			currentOrdinal++;
		}
		int numUndefinedsAfter = structLength - currentOffset;
		componentCount += numUndefinedsAfter;
		if (updateNumComponents(componentCount)) {
			changed = true;
		}
		return changed;
	}

	private boolean updateNumComponents(int currentNumComponents) {
		if (numComponents != currentNumComponents) {
			numComponents = currentNumComponents;
			return true;
		}
		return false;
	}

	private boolean updateComposite(int currentNumComponents, int currentLength) {
		boolean compositeChanged = false;
		if (numComponents != currentNumComponents) {
			numComponents = currentNumComponents;
			compositeChanged = true;
		}
		if (structLength != currentLength) {
			structLength = currentLength;
			compositeChanged = true;
		}
		return compositeChanged;
	}

	private boolean alignEndOfStruct(int componentLCM) {
		int minimumAlignment = getMinimumAlignment();
		int structureLength = getLength();
		if (structureLength == 0) {
			return true;
		}
		int overallAlignment = componentLCM;
		if (minimumAlignment > overallAlignment) {
			// TODO Should this actually get the LeastCommonMultiple of minimumAlignment and overallAlignment?
			overallAlignment = minimumAlignment;
		}
		int padSize = DataOrganizationImpl.getPaddingSize(overallAlignment, structLength);
		if (padSize > 0) {
			doGrowStructure(padSize);
			return true;
		}
		return false;
	}

	private void doGrowStructure(int amount) {
		if (!isInternallyAligned()) {
			numComponents += amount;
		}
		structLength += amount;
	}

	@Override
	public void adjustInternalAlignment() {
		adjustComponents();
	}

	@Override
	public boolean hasFlexibleArrayComponent() {
		return flexibleArrayComponent != null;
	}

	@Override
	public DataTypeComponent getFlexibleArrayComponent() {
		return flexibleArrayComponent;
	}

	@Override
	public DataTypeComponent setFlexibleArrayComponent(DataType flexType, String name,
			String comment) {
		return doAdd(flexType, 0, name, comment, true, true);
	}

	@Override
	public void clearFlexibleArrayComponent() {
		if (flexibleArrayComponent == null) {
			return;
		}
		flexibleArrayComponent = null;
		adjustInternalAlignment();
		notifySizeChanged();
	}

	@Override
	protected void dumpComponents(StringBuilder buffer, String pad) {
		super.dumpComponents(buffer, pad);
		DataTypeComponent dtc = getFlexibleArrayComponent();
		if (dtc != null) {
			DataType dataType = dtc.getDataType();
			buffer.append(pad + dataType.getDisplayName() + "[0]");
			buffer.append(pad + dtc.getLength());
			buffer.append(pad + dtc.getFieldName());
			String comment = dtc.getComment();
			if (comment == null) {
				comment = "";
			}
			buffer.append(pad + "\"" + comment + "\"");
			buffer.append("\n");
		}
	}
}

class OffsetComparator implements Comparator<Object> {

	/**
	 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
	 */
	@Override
	public int compare(Object o1, Object o2) {
		if (o1 instanceof Integer) {
			return -compare(o2, o1);
		}
		DataTypeComponent dtc = (DataTypeComponent) o1;
		int offset = ((Integer) o2).intValue();
		if (offset < dtc.getOffset()) {
			return 1;
		}
		else if (offset > dtc.getEndOffset()) {
			return -1;
		}
		return 0;
	}

}

class OrdinalComparator implements Comparator<Object> {

	/**
	 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
	 */
	@Override
	public int compare(Object o1, Object o2) {
		if (o1 instanceof Integer) {
			return -compare(o2, o1);
		}
		DataTypeComponent dtc = (DataTypeComponent) o1;
		int ordinal = ((Integer) o2).intValue();
		return dtc.getOrdinal() - ordinal;
	}

}
