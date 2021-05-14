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

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;
import ghidra.util.UniversalID;

/**
 * Basic implementation of the union data type.
 * NOTE: Implementation is not thread safe when being modified.
 */
public class UnionDataType extends CompositeDataTypeImpl implements UnionInternal {

	private int unionLength;
	private int unionAlignment;

	private List<DataTypeComponentImpl> components;

	/**
	 * Construct a new empty union with the given name within the
	 * specified categry path.  An empty union will report its length as 1 and 
	 * {@link #isNotYetDefined()} will return true.
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new union
	 */
	public UnionDataType(CategoryPath path, String name) {
		this(path, name, null);
	}

	/**
	 * Construct a new empty union with the given name and datatype manager
	 * within the specified categry path.  An empty union will report its 
	 * length as 1 and {@link #isNotYetDefined()} will return true.
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new union
	 * @param dtm the data type manager associated with this data type. This can be null. 
	 * Also, the data type manager may not yet contain this actual data type.
	 */
	public UnionDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
		components = new ArrayList<>();
	}

	/**
	 * Construct a new empty union with the given name within the specified categry path.
	 * An empty union will report its length as 1 and {@link #isNotYetDefined()} 
	 * will return true.
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new structure
	 * @param universalID the id for the data type
	 * @param sourceArchive the source archive for this data type
	 * @param lastChangeTime the last time this data type was changed
	 * @param lastChangeTimeInSourceArchive the last time this data type was changed in
	 * its source archive.
	 * @param dtm the data type manager associated with this data type. This can be null. 
	 * Also, the data type manager may not contain this actual data type.
	 */
	public UnionDataType(CategoryPath path, String name, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dtm) {
		super(path, name, universalID, sourceArchive, lastChangeTime, lastChangeTimeInSourceArchive,
			dtm);

		components = new ArrayList<>();
	}

	/**
	 * Construct a new UnionDataType
	 * @param name the name of this dataType
	 */
	public UnionDataType(String name) {
		this(CategoryPath.ROOT, name);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (isNotYetDefined()) {
			return "<Empty-Union>";
		}
		return "";
	}

	@Override
	public boolean isNotYetDefined() {
		return unionLength == 0 && isDefaultAligned() && !isPackingEnabled();
	}

	@Override
	public DataTypeComponent getComponent(int ordinal) {
		return components.get(ordinal);
	}

	@Override
	public DataTypeComponent[] getComponents() {
		return components.toArray(new DataTypeComponent[components.size()]);
	}

	@Override
	public DataTypeComponent[] getDefinedComponents() {
		return getComponents();
	}

	@Override
	public int getNumComponents() {
		return components.size();
	}

	@Override
	public int getNumDefinedComponents() {
		return components.size();
	}

	@Override
	protected int getPreferredComponentLength(DataType dataType, int length) {
		if (!(dataType instanceof Dynamic)) {
			length = -1;
		}
		return super.getPreferredComponentLength(dataType, length);
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String componentName,
			String comment) throws IllegalArgumentException {

		int oldAlignment = getAlignment();

		DataTypeComponent dtc = doAdd(dataType, length, componentName, comment);
		if (!repack(true) && isPackingEnabled() && oldAlignment != getAlignment()) {
			notifyAlignmentChanged();
		}
		return dtc;
	}

	private int getBitFieldAllocation(BitFieldDataType bitfieldDt) {

		BitFieldPacking bitFieldPacking = getDataOrganization().getBitFieldPacking();
		if (bitFieldPacking.useMSConvention()) {
			return bitfieldDt.getBaseTypeSize();
		}

		if (bitfieldDt.getBitSize() == 0) {
			return 0;
		}

		int length = bitfieldDt.getBaseTypeSize();
		if (packing > 0 && length > packing) {
			length =
				DataOrganizationImpl.getLeastCommonMultiple(bitfieldDt.getStorageSize(), packing);
		}
		return length;
	}

	DataTypeComponent doAdd(DataType dataType, int length, String componentName, String comment)
			throws IllegalArgumentException {

		dataType = validateDataType(dataType);

		dataType = adjustBitField(dataType);

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		length = getPreferredComponentLength(dataType, length);

		DataTypeComponentImpl dtc = new DataTypeComponentImpl(dataType, this, length,
			components.size(), 0, componentName, comment);
		dataType.addParent(this);
		components.add(dtc);

		return dtc;
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length,
			String componentName, String comment) throws IllegalArgumentException {
		dataType = validateDataType(dataType);

		int oldAlignment = getAlignment();

		dataType = adjustBitField(dataType);

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		length = getPreferredComponentLength(dataType, length);

		DataTypeComponentImpl dtc =
			new DataTypeComponentImpl(dataType, this, length, ordinal, 0, componentName, comment);
		dataType.addParent(this);
		shiftOrdinals(ordinal, 1);
		components.add(ordinal, dtc);

		if (!repack(true) && isPackingEnabled() && oldAlignment != getAlignment()) {
			notifyAlignmentChanged();
		}
		return dtc;
	}

	@Override
	public DataTypeComponent addBitField(DataType baseDataType, int bitSize, String componentName,
			String comment) throws InvalidDataTypeException {
		return insertBitField(components.size(), baseDataType, bitSize, componentName, comment);
	}

	@Override
	public DataTypeComponent insertBitField(int ordinal, DataType baseDataType, int bitSize,
			String componentName, String comment)
			throws InvalidDataTypeException, IndexOutOfBoundsException {

		if (ordinal < 0 || ordinal > components.size()) {
			throw new IndexOutOfBoundsException(ordinal);
		}

		BitFieldDataType.checkBaseDataType(baseDataType);
		baseDataType = baseDataType.clone(dataMgr);

		BitFieldDataType bitFieldDt = new BitFieldDataType(baseDataType, bitSize);
		return insert(ordinal, bitFieldDt, bitFieldDt.getStorageSize(), componentName, comment);
	}

	@Override
	public boolean isZeroLength() {
		return unionLength == 0;
	}

	@Override
	public int getLength() {
		if (unionLength == 0) {
			return 1; // 0-length datatype not supported
		}
		return unionLength;
	}

	@Override
	public boolean hasLanguageDependantLength() {
		// Assume any component may have a language-dependent length
		return true;
	}

	@Override
	public Union clone(DataTypeManager dtm) {
		if (dataMgr == dtm) {
			return this;
		}
		UnionDataType union = new UnionDataType(getCategoryPath(), getName(), getUniversalID(),
			getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		union.setDescription(getDescription());
		union.replaceWith(this);
		return union;
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		UnionDataType union = new UnionDataType(getCategoryPath(), getName(), dtm);
		union.setDescription(getDescription());
		union.replaceWith(this);
		return union;
	}

	@Override
	public void delete(int ordinal) {

		int oldAlignment = getAlignment();

		DataTypeComponent dtc = components.remove(ordinal);
		dtc.getDataType().removeParent(this);
		shiftOrdinals(ordinal, -1);

		if (!repack(true) && isPackingEnabled() && oldAlignment != getAlignment()) {
			notifyAlignmentChanged();
		}
	}

	@Override
	public void delete(Set<Integer> ordinals) {

		if (ordinals.isEmpty()) {
			return;
		}

		int oldAlignment = getAlignment();

		List<DataTypeComponentImpl> newComponents = new ArrayList<>();
		int newLength = 0;
		int ordinalAdjustment = 0;
		for (DataTypeComponentImpl dtc : components) {
			int ordinal = dtc.getOrdinal();
			if (ordinals.contains(ordinal)) {
				// component removed
				--ordinalAdjustment;
			}
			else {
				if (ordinalAdjustment != 0) {
					dtc.setOrdinal(dtc.getOrdinal() + ordinalAdjustment);
				}
				newComponents.add(dtc);
				newLength = Math.max(newLength, dtc.getLength());
			}
		}
		components = newComponents;

		if (isPackingEnabled()) {
			if (!repack(true) && oldAlignment != getAlignment()) {
				notifyAlignmentChanged();
			}
		}
		else {
			unionLength = newLength;
			notifySizeChanged();
		}
	}

	private DataType adjustBitField(DataType dataType) {

		if (!(dataType instanceof BitFieldDataType)) {
			return dataType;
		}

		BitFieldDataType bitfieldDt = (BitFieldDataType) dataType;

		DataType baseDataType = bitfieldDt.getBaseDataType();
		baseDataType = baseDataType.clone(dataMgr);

		// Both aligned and non-packed bitfields use same adjustment
		// non-packed must force bitfield placement at byte offset 0 
		int bitSize = bitfieldDt.getDeclaredBitSize();
		int effectiveBitSize =
			BitFieldDataType.getEffectiveBitSize(bitSize, baseDataType.getLength());

		// little-endian always uses bit offset of 0 while
		// big-endian offset must be computed
		boolean bigEndian = getDataOrganization().isBigEndian();
		int storageBitOffset = 0;
		if (bigEndian) {
			if (bitSize == 0) {
				storageBitOffset = 7;
			}
			else {
				int storageSize = BitFieldDataType.getMinimumStorageSize(effectiveBitSize);
				storageBitOffset = (8 * storageSize) - effectiveBitSize;
			}
		}

		if (effectiveBitSize != bitfieldDt.getBitSize() ||
			storageBitOffset != bitfieldDt.getBitOffset()) {
			try {
				bitfieldDt = new BitFieldDataType(baseDataType, effectiveBitSize, storageBitOffset);
			}
			catch (InvalidDataTypeException e) {
				// unexpected since deriving from existing bitfield,
				// ignore and use existing bitfield
			}
		}
		return bitfieldDt;
	}

	@Override
	public int getAlignment() {
		if (unionAlignment > 0) {
			return unionAlignment;
		}
		if (isPackingEnabled()) {
			unionAlignment = CompositeAlignmentHelper.getAlignment(getDataOrganization(), this);
		}
		else {
			unionAlignment = getNonPackedAlignment();
		}
		return unionAlignment;
	}

	@Override
	public boolean repack(boolean notify) {

		int oldLength = unionLength;
		int oldAlignment = getAlignment();

		unionLength = 0;
		for (DataTypeComponent dtc : components) {
			// TODO: compute alignment in this loop
			int length = dtc.getLength();
			if (isPackingEnabled() && dtc.isBitFieldComponent()) {
				// revise length to reflect compiler bitfield allocation rules
				length = getBitFieldAllocation((BitFieldDataType) dtc.getDataType());
			}
			unionLength = Math.max(length, unionLength);
		}
		
		unionAlignment = -1; // force recompute of unionAlignment
		getAlignment();

		if (isPackingEnabled()) {
			unionLength = DataOrganizationImpl.getAlignedOffset(unionAlignment, unionLength);
		}

		boolean changed = (oldLength != unionLength) || (oldAlignment != unionAlignment);

		if (changed && notify) {
			if (oldLength != unionLength) {
				notifySizeChanged();
			}
			else if (oldAlignment != unionAlignment) {
				notifyAlignmentChanged();
			}
		}
		return changed;
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null) {
			return false;
		}

		if (dt instanceof UnionInternal) {
			UnionInternal union = (UnionInternal) dt;
			if (packing != union.getStoredPackingValue() ||
				minimumAlignment != union.getStoredMinimumAlignment()) {
				// rely on component match instead of checking length 
				// since dynamic component sizes could affect length
				return false;
			}
			DataTypeComponent[] myComps = getComponents();
			DataTypeComponent[] otherComps = union.getComponents();
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

	private void shiftOrdinals(int ordinal, int deltaOrdinal) {
		for (int i = ordinal; i < components.size(); i++) {
			DataTypeComponentImpl dtc = components.get(i);
			dtc.setOrdinal(dtc.getOrdinal() + deltaOrdinal);
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		if (!isPackingEnabled()) {
			return;
		}
		if (dt instanceof BitFieldDataType) {
			return; // unsupported
		}
		boolean hasPossibleChange = false;
		for (DataTypeComponentImpl dtc : components) {
			if (dtc.getDataType() == dt) {
				hasPossibleChange = true;
				break;
			}
		}
		if (hasPossibleChange && !repack(true) && isPackingEnabled()) {
			// NOTE: Must assume alignment change since we are unable to determine
			// without stored alignment
			notifyAlignmentChanged();
		}
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		if (dt instanceof BitFieldDataType) {
			return; // unsupported
		}
		boolean changed = false;
		for (DataTypeComponentImpl dtc : components) {
			if (dtc.getDataType() == dt) {
				int length = dt.getLength();
				if (length <= 0) {
					length = dtc.getLength();
				}
				dtc.setLength(length);
				changed = true;
			}
		}
		if (changed && !repack(true) && isPackingEnabled()) {
			// NOTE: Must assume alignment change since we are unable to determine
			// without stored alignment
			notifyAlignmentChanged();
		}
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) throws IllegalArgumentException {
		DataType replacementDt = newDt;
		try {
			validateDataType(replacementDt);
			if (replacementDt.getDataTypeManager() != dataMgr) {
				replacementDt = replacementDt.clone(dataMgr);
			}
			checkAncestry(replacementDt);
		}
		catch (Exception e) {
			// TODO: should we use Undefined instead since we do not support
			// DEFAULT in Unions
			replacementDt = DataType.DEFAULT;
		}
		boolean changed = false;
		for (int i = components.size() - 1; i >= 0; i--) {

			DataTypeComponentImpl dtc = components.get(i);

			boolean remove = false;
			if (dtc.isBitFieldComponent()) {
				try {
					changed |= updateBitFieldDataType(dtc, oldDt, replacementDt);
				}
				catch (InvalidDataTypeException e) {
					Msg.error(this,
						"Invalid bitfield replacement type " + newDt.getName() +
							", removing bitfield " + dtc.getDataType().getName() + ": " +
							getPathName());
					remove = true;
				}
			}
			else if (dtc.getDataType() == oldDt) {
				if (replacementDt == DEFAULT) {
					Msg.error(this,
						"Invalid replacement type " + newDt.getName() + ", removing component " +
							dtc.getDataType().getName() + ": " + getPathName());
					remove = true;
				}
				else {
					oldDt.removeParent(this);
					dtc.setDataType(replacementDt);
					replacementDt.addParent(this);
					int len = replacementDt.getLength();
					if (len > 0) {
						dtc.setLength(len);
					}
					changed = true;
				}
			}
			if (remove) {
				// error case - remove component
				oldDt.removeParent(this);
				components.remove(i);
				shiftOrdinals(i, -1);
				changed = true;
			}
		}
		if (changed) {
			repack(false);
			notifySizeChanged();
		}
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		boolean changed = false;
		for (int i = components.size() - 1; i >= 0; i--) { // reverse order
			DataTypeComponentImpl dtc = components.get(i);
			boolean removeBitFieldComponent = false;
			if (dtc.isBitFieldComponent()) {
				BitFieldDataType bitfieldDt = (BitFieldDataType) dtc.getDataType();
				removeBitFieldComponent = bitfieldDt.getBaseDataType() == dt;
			}
			if (removeBitFieldComponent || dtc.getDataType() == dt) {
				dt.removeParent(this);
				components.remove(i);
				shiftOrdinals(i, -1);
				changed = true;
			}
		}
		if (changed && !repack(true) && isPackingEnabled()) {
			// NOTE: Must assume alignment change since we are unable to determine
			// without stored alignment
			notifyAlignmentChanged();
		}
	}

	@Override
	public void replaceWith(DataType dataType) throws IllegalArgumentException {
		if (!(dataType instanceof UnionInternal)) {
			throw new IllegalArgumentException();
		}

		UnionInternal union = (UnionInternal) dataType;

		Iterator<DataTypeComponentImpl> it = components.iterator();
		while (it.hasNext()) {
			DataTypeComponent dtc = it.next();
			dtc.getDataType().removeParent(this);
		}
		components.clear();
		unionAlignment = -1;

		this.packing = union.getStoredPackingValue();
		this.minimumAlignment = union.getStoredMinimumAlignment();

		DataTypeComponent[] compArray = union.getComponents();
		for (DataTypeComponent dtc : compArray) {
			DataType dt = dtc.getDataType();
			doAdd(dt, dtc.getLength(), dtc.getFieldName(), dtc.getComment());
		}

		repack(false);
		notifySizeChanged(); // assume size and/or alignment changed
	}

	@Override
	public boolean dependsOn(DataType dt) {
		if (getNumComponents() == 1) {
			DataTypeComponent dtc = getComponent(0);
			return dtc.getDataType().dependsOn(dt);
		}
		return false;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "UNION_" + getName();
	}

}
