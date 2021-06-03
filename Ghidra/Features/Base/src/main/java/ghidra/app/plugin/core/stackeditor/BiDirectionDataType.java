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
package ghidra.app.plugin.core.stackeditor;

import java.util.*;

import javax.help.UnsupportedOperationException;

import ghidra.program.model.data.*;
import ghidra.util.exception.AssertException;

/**
 * BiDirectionDataType is a special structure data type that allows both positive and negative
 * offset values.
 */
public abstract class BiDirectionDataType extends StructureDataType
		implements BiDirectionStructure {

	protected static Comparator<Object> ordinalComparator = new OrdinalComparator();
	protected static Comparator<Object> offsetComparator = new OffsetComparator();
	protected int negativeLength;
	protected int positiveLength;
	protected int splitOffset; // division offset between negative/positive halves

	/**
	 * @param name
	 * @param length
	 */
	protected BiDirectionDataType(String name, int negativeLength, int positiveLength,
			int splitOffset, DataTypeManager dtm) {
		super(CategoryPath.ROOT, name, negativeLength + positiveLength, dtm);
		this.negativeLength = negativeLength;
		this.positiveLength = positiveLength;
		this.splitOffset = splitOffset;
	}

	protected BiDirectionDataType(CategoryPath catPath, String name, int negativeLength,
			int positiveLength, int splitOffset, DataTypeManager dtm) {
		super(catPath, name, negativeLength + positiveLength, dtm);
		this.negativeLength = negativeLength;
		this.positiveLength = positiveLength;
		this.splitOffset = splitOffset;
	}

	@Override
	public int getAlignment() {
		throw new UnsupportedOperationException(
			"BiDirectionDataType.getAlignment() not implemented.");
	}

	@Override
	public boolean repack(boolean notify) {
		throw new AssertException();
	}

	@Override
	public void setToDefaultAligned() {
		// ignore
	}

	@Override
	public void setToMachineAligned() {
		// ignore
	}

	@Override
	public void setPackingEnabled(boolean aligned) {
		// ignore
	}

	@Override
	public void setExplicitPackingValue(int packingValue) {
		// ignore
	}

	@Override
	public void setExplicitMinimumAlignment(int minimumAlignment) {
		// ignore
	}

	@Override
	public DataTypeComponent setFlexibleArrayComponent(DataType flexType, String name,
			String comment) {
		throw new UnsupportedOperationException(
			"BiDirectionDataType.setFlexibleArrayComponent() not implemented.");
	}

	protected DataTypeComponent getDefinedComponentAt(int offset) {
		if (offset < splitOffset - negativeLength || offset >= splitOffset + positiveLength) {
			return null;
		}
		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);
		if (index >= 0) {
			return components.get(index);
		}
		return null;
	}

	@Override
	public DataTypeComponent getComponentAt(int offset) {
		if (offset < splitOffset - negativeLength || offset >= splitOffset + positiveLength) {
			return null;
		}
		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);
		if (index >= 0) {
			return components.get(index);
		}
		int ordinal = 0;
		index = -index - 1;
		int prevIndex = index - 1;
		if (prevIndex < 0) {
			ordinal = offset + negativeLength - splitOffset;
		}
		else {
			DataTypeComponent prevComp = components.get(prevIndex);
			int prevOrdinal = prevComp.getOrdinal();
			int prevOffset = prevComp.getOffset();
			int endOffset = prevComp.getEndOffset();
			if (offset > prevOffset && offset <= endOffset) {
				return null;
			}
			ordinal = prevOrdinal + offset - endOffset;
		}
		return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
	}

	@Override
	public int getSplitOffset() {
		return splitOffset;
	}

	@Override
	public int getNegativeLength() {
		return negativeLength;
	}

	@Override
	public int getPositiveLength() {
		return positiveLength;
	}

	@Override
	public void delete(int index) {
		if (index < 0 || index >= numComponents) {
			throw new IndexOutOfBoundsException(index);
		}
		DataTypeComponent comp = getComponent(index);
		int offset = comp.getOffset();
		int length = comp.getLength();
		int idx = Collections.binarySearch(components, index, ordinalComparator);
		if (idx >= 0) {
			DataTypeComponent dtc = components.remove(idx);
			dtc.getDataType().removeParent(this);
			length = dtc.getLength();
		}
		else {
			idx = -idx - 1;
			length = 1;
		}
		adjustOffsets(idx, offset, -1, -length);
		numComponents--;
		notifySizeChanged();
	}

	@Override
	public void delete(Set<Integer> ordinals) {
		for (int ordinal : ordinals) {
			delete(ordinal);
		}
	}

	/**
	 * 
	 * @param idx the min index in the defined component arraylist
	 * @param offset
	 * @param deltaOrdinal
	 * @param deltaLength
	 */
	protected void adjustOffsets(int idx, int offset, int deltaOrdinal, int deltaLength) {
		if (offset >= splitOffset) {
			// component was in positive offsets
			shiftOffsets(idx, deltaOrdinal, deltaLength);
			positiveLength += deltaLength;
		}
		else {
			if (offset - deltaLength > splitOffset) {
				// The deleted component straddled negative/zero boudary.
				shiftOffsets(0, idx - 1, 0, offset);
				shiftOffsets(idx, deltaOrdinal, offset - deltaLength);
// TODO: this seems wrong
				negativeLength += offset;
				positiveLength -= (offset - deltaLength);
			}
			else {
				// component was in negative offsets
				shiftOffsets(0, idx - 1, 0, -deltaLength);
				shiftOffsets(idx, deltaOrdinal, 0);
				negativeLength += deltaLength;
			}
		}
		structLength += deltaLength;
//		nonpackedAlignedStructLength = -1;
	}

	/*
	 * 
	 */
	private void shiftOffsets(int index, int deltaOrdinal, int deltaOffset) {
		shiftOffsets(index, components.size() - 1, deltaOrdinal, deltaOffset);
	}

	/**
	 * 
	 * @param startIndex the min index in the defined component arraylist
	 * @param endIndex the max index in the defined component arraylist
	 * @param deltaOrdinal
	 * @param deltaOffset
	 */
	protected void shiftOffsets(int startIndex, int endIndex, int deltaOrdinal, int deltaOffset) {
		for (int i = startIndex; i <= endIndex && i < components.size(); i++) {
			DataTypeComponentImpl dtc = components.get(i);
			shiftOffset(dtc, deltaOrdinal, deltaOffset);
		}
	}

	protected DataTypeComponent getDefinedComponent(int ordinal) {
		if (ordinal < 0 || ordinal >= numComponents) {
			throw new IndexOutOfBoundsException(ordinal);
		}
		int idx = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
		if (idx >= 0) {
			return components.get(idx);
		}
		return null;
	}

	@Override
	public DataTypeComponent getComponent(int ordinal) {
		if (ordinal < 0 || ordinal >= numComponents) {
			throw new IndexOutOfBoundsException(ordinal);
		}
		int idx = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
		if (idx >= 0) {
			return components.get(idx);
		}
		idx = -idx - 1;
		int prevIndex = idx - 1;
		int offset = computeOffset(ordinal, prevIndex);
		return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
	}

	protected int computeOffset(int ordinal, int prevIndex) {
		int offset;
		if (prevIndex < 0) {
			offset = splitOffset - negativeLength + ordinal;
		}
		else {
			DataTypeComponent prevElement = components.get(prevIndex);
			int prevOrdinal = prevElement.getOrdinal();
			int endOffset = prevElement.getEndOffset();
			offset = endOffset + ordinal - prevOrdinal;
		}
		return offset;
	}

	@Override
	public int getNumComponents() {
		return numComponents;
	}

	@Override
	public DataTypeComponentImpl insertAtOffset(int offset, DataType dataType, int length,
			String newName, String comment) throws IllegalArgumentException {
		if (offset < splitOffset - negativeLength || offset >= splitOffset + positiveLength) {
			throw new IllegalArgumentException(
				"Offset " + offset + " is not in " + getDisplayName() + ".");
		}
		validateDataType(dataType);
		int nextOffset = offset + length;
		if (offset > positiveLength) {
			int deltaLength = offset - positiveLength;
			numComponents += deltaLength;
			positiveLength += deltaLength;
			structLength += deltaLength;
//			nonpackedAlignedStructLength = -1;
		}
		if (nextOffset < splitOffset - negativeLength) {
			int deltaLength = splitOffset - nextOffset - negativeLength;
			numComponents += deltaLength;
			negativeLength += deltaLength;
			structLength += deltaLength;
//			nonpackedAlignedStructLength = -1;
		}
		checkAncestry(dataType);
		dataType = dataType.clone(getDataTypeManager());

		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);

		int additionalShift = 0;
		if (index >= 0) {
			DataTypeComponent dtc = components.get(index);
			if (offset < 0) {
				additionalShift = offset - dtc.getEndOffset();
			}
			else {
				additionalShift = offset - dtc.getOffset();
			}
		}
		else {
			index = -index - 1;
		}
// TODO: ??
		int ordinal = negativeLength + offset;
		if (index > 0) {
			DataTypeComponent dtc = components.get(index - 1);
			ordinal = dtc.getOrdinal() + offset - dtc.getEndOffset();
		}

		DataTypeComponentImpl dtc =
			new DataTypeComponentImpl(dataType, this, length, ordinal, offset, newName, comment);
		dataType.addParent(this);
		adjustOffsets(index, offset, 1 + additionalShift, dtc.getLength() + additionalShift);
		components.add(index, dtc);
		numComponents++;
		notifySizeChanged();
		return dtc;
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String newName, String comment) {
		return addPositive(dataType, length, newName, comment);
	}

	@Override
	public DataTypeComponent addPositive(DataType dataType, int length, String newName,
			String comment) throws IllegalArgumentException {

		validateDataType(dataType);
		checkAncestry(dataType);
		dataType = dataType.clone(getDataTypeManager());
//		int dtLength = dataType.getLength();

		int offset = positiveLength;
		DataTypeComponentImpl dtc = new DataTypeComponentImpl(dataType, this, length, numComponents,
			offset, newName, comment);
		dataType.addParent(this);
		components.add(dtc);
		numComponents++;
		positiveLength += length;
		structLength += length;
//		nonpackedAlignedStructLength = -1;
		notifySizeChanged();
		return dtc;
	}

	@Override
	public DataTypeComponent addNegative(DataType dataType, int length, String newName,
			String comment) throws IllegalArgumentException {

		validateDataType(dataType);
		checkAncestry(dataType);
		dataType = dataType.clone(getDataTypeManager());
//		int dtLength = dataType.getLength();

		shiftOffsets(0, numComponents - 1, 1, 0);
		int offset = splitOffset - negativeLength - length;
		DataTypeComponentImpl dtc =
			new DataTypeComponentImpl(dataType, this, length, 0, offset, newName, comment);
		dataType.addParent(this);
		components.add(dtc);
		numComponents++;
		negativeLength += length;
		structLength += length;
//		nonpackedAlignedStructLength = -1;
		notifySizeChanged();
		return dtc;
	}

	/**
	 * Increases the size of the bidirectional data type If amount is positive then the positive
	 * offset side will grow by the indicated amount. If amount is negative, the data type grows on
	 * the negative offsets side.
	 * 
	 * @param amount Positive value indicates number of bytes to add to positive side. Negative
	 *            value indicates number of bytes to add to negative side.
	 */
	@Override
	public void growStructure(int amount) {
		int absAmount;
		if (amount < 0) {
			absAmount = -amount;
			negativeLength -= amount;
			adjustOffsets(0, negativeLength, absAmount, 0);
		}
		else {
			absAmount = amount;
			positiveLength += amount;
		}
		numComponents += absAmount;
		structLength += absAmount;
//		nonpackedAlignedStructLength = -1;
		notifySizeChanged();
	}

	@Override
	public DataTypeComponent insert(int index, DataType dataType, int length, String newName,
			String comment) {
		throw new UnsupportedOperationException("BiDirectionDataType.insert() not implemented.");
	}

	protected void insertAtOffset(int offset, int numBytes) {
		if (offset < splitOffset - negativeLength || offset > splitOffset + positiveLength) {
			throw new IllegalArgumentException("Offset " + offset +
				" is not a valid insertion point in " + getDisplayName() + ".");
		}
		DataTypeComponent dtc = getComponentAt(offset);
		int numDefinedComponents = components.size();
		int definedIndex = 0;
		if (dtc == null) {
			if (offset == positiveLength) {
				definedIndex = numDefinedComponents;
			}
			else {
				throw new IllegalArgumentException("Offset " + offset +
					" is not a valid insertion point in " + getDisplayName() + ".");
			}
		}
		else if (dtc.getOffset() != offset) {
			throw new IllegalArgumentException("Cannot insert at offset " + offset +
				" within a defined component in " + getDisplayName() + ".");
		}
		else {
			definedIndex = Collections.binarySearch(components, new Integer(dtc.getOrdinal()),
				ordinalComparator);
			if (definedIndex < 0) {
				definedIndex = -definedIndex - 1;
			}
		}
		if (offset <= 0) {
			shiftOffsets(0, definedIndex - 1, 0, -numBytes);
			shiftOffsets(definedIndex, numDefinedComponents - 1, numBytes, 0);
			negativeLength += numBytes;
		}
		else {
			shiftOffsets(definedIndex, numDefinedComponents - 1, numBytes, numBytes);
			positiveLength += numBytes;
		}
		numComponents += numBytes;
		structLength += numBytes;
//		nonpackedAlignedStructLength = -1;
		notifySizeChanged();
	}

	@Override
	public void deleteAtOffset(int offset) {
		if (offset < splitOffset - negativeLength || offset >= splitOffset + positiveLength) {
			throw new IllegalArgumentException(
				"Offset " + offset + " is not in " + getDisplayName() + ".");
		}
		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);

		int length = 1;
		if (index < 0) {
			index = -index - 1;
		}
		else {
			DataTypeComponent dtc = components.remove(index);
			dtc.getDataType().removeParent(this);
			length = dtc.getLength();
		}
		adjustOffsets(index, offset, -1, -length);
		numComponents--;
	}

	@Override
	public boolean isEquivalent(DataType dataType) {
		if (dataType == this) {
			return true;
		}
		if (dataType == null) {
			return false;
		}

		if (dataType instanceof BiDirectionStructure) {
			BiDirectionStructure biDir = (BiDirectionStructure) dataType;
			if ((splitOffset != biDir.getSplitOffset()) ||
				(negativeLength != biDir.getNegativeLength()) ||
				(positiveLength != biDir.getPositiveLength()) ||
				(getLength() != biDir.getLength())) {
				return false;
			}
			DataTypeComponent[] myComps = getDefinedComponents();
			DataTypeComponent[] otherComps = biDir.getDefinedComponents();
			if (myComps.length != otherComps.length) {
				return false;
			}
			for (int i = 0; i < myComps.length; i++) {
				if (!myComps[i].isEquivalent(otherComps[i])) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		// ignore
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		// ignore
	}

	@Override
	public abstract BiDirectionDataType clone(DataTypeManager dtm);

	@Override
	public void clearComponent(int index) {
		if (index < 0 || index >= numComponents) {
			throw new IndexOutOfBoundsException(index);
		}
		int idx = Collections.binarySearch(components, new Integer(index), ordinalComparator);
		if (idx >= 0) {
			DataTypeComponent dtc = components.remove(idx);
			dtc.getDataType().removeParent(this);
			int len = dtc.getLength();
			int deltaLength = len - 1;
//			int offset = dtc.getOffset();
			if (len > 1) {
				shiftOffsets(idx, deltaLength, 0);
				numComponents += deltaLength;
			}
		}
	}

	public void replaceWith(Structure struct) {
		throw new UnsupportedOperationException(
			"BiDirectionDataType.replaceWith() not implemented.");
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		throw new UnsupportedOperationException(
			"BiDirectionDataType.dataTypeDeleted() not implemented.");
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		throw new UnsupportedOperationException(
			"BiDirectionDataType.dataTypeReplaced() not implemented.");
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
	public DataTypeComponent replace(int index, DataType dataType, int length, String newName,
			String comment) throws IndexOutOfBoundsException, IllegalArgumentException {
		if (index < 0 || index >= numComponents) {
			throw new IndexOutOfBoundsException(index);
		}
		validateDataType(dataType);
		checkAncestry(dataType);
		dataType = dataType.clone(getDataTypeManager());
		DataTypeComponent origDtc = getComponent(index);
		return replace(origDtc, dataType, length, newName, comment);
	}

	@Override
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length,
			String newName, String comment) throws IllegalArgumentException {
		if (offset < splitOffset - negativeLength || offset >= splitOffset + positiveLength) {
			throw new IllegalArgumentException(
				"Offset " + offset + " is not in " + getDisplayName() + ".");
		}
		validateDataType(dataType);
		checkAncestry(dataType);
		dataType = dataType.clone(getDataTypeManager());
		DataTypeComponent origDtc = getComponentAt(offset);
		DataTypeComponent newDtc = replace(origDtc, dataType, length, newName, comment);
		return newDtc;
	}

	/**
	 * Replace the indicated component with a new component containing the specified data type.
	 * 
	 * @param origDtc the original data type component in this structure.
	 * @param dataType the data type of the new component
	 * @param length the length of the new component
	 * @param newName the field name of the new component
	 * @param comment the comment for the new component
	 * @return the new component or null if the new component couldn't fit.
	 * @throws IllegalArgumentException if the dataType.getLength() is positive and does not match
	 *             the given length parameter.
	 * @throws IllegalArgumentException if the specified data type is not allowed to replace a
	 *             component in this composite data type. For example, suppose dt1 contains dt2.
	 *             Therefore it is not valid to replace a dt2 component with dt1 since this would
	 *             cause a cyclic dependency.
	 */
	private DataTypeComponent replace(DataTypeComponent origDtc, DataType dataType, int length,
			String newName, String comment) {

		int ordinal = origDtc.getOrdinal();
		int newOffset = origDtc.getOffset();
		int dtcLength = origDtc.getLength();
		int bytesNeeded = length - dtcLength;
		int deltaOrdinal = -bytesNeeded;
		if (bytesNeeded > 0) {
			int bytesAvailable = getNumUndefinedBytes(ordinal + 1);
			if (bytesAvailable < bytesNeeded) {
//				throw new IllegalArgumentException("Not enough undefined bytes.");
				deltaOrdinal = -bytesAvailable;
				length -= (bytesNeeded - bytesAvailable);
			}
		}
		origDtc.getDataType().removeParent(this);
		DataTypeComponentImpl newDtc =
			new DataTypeComponentImpl(dataType, this, length, ordinal, newOffset, newName, comment);
		dataType.addParent(this);
		int index = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
		if (index < 0) {
			index = -index - 1;
		}
		else {
			components.remove(index);
		}
		if (deltaOrdinal != 0) {
			adjustOffsets(index, newOffset, deltaOrdinal, 0);
		}
		components.add(index, newDtc);
		if (deltaOrdinal != 0) {
			numComponents += deltaOrdinal;
		}
		return newDtc;
	}

}

class OffsetComparator implements Comparator<Object> {

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
