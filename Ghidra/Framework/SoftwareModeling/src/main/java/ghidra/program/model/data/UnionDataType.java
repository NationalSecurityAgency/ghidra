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

import java.util.ArrayList;
import java.util.Iterator;

import ghidra.app.plugin.core.datamgr.archive.SourceArchive;
import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.UniversalID;

/**
 * Basic implementation of the union data type
 */
public class UnionDataType extends CompositeDataTypeImpl implements Union {
	private ArrayList<DataTypeComponent> components;
	private int unionLength;

	/**
	 * Construct a new UnionDataType
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of this dataType
	 */
	public UnionDataType(CategoryPath path, String name) {
		this(path, name, null);
	}

	public UnionDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
		components = new ArrayList<>();
	}

	/**
	 * Construct a new UnionDataType
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of this dataType
	 * @param dataTypeManager the data type manager associated with this data type. This can be null. 
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

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.util.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (isNotYetDefined()) {
			return "<Empty-Union>";
		}
		return "";
	}

	@Override
	public boolean isNotYetDefined() {
		return components.size() == 0;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#getComponent(int)
	 */
	@Override
	public DataTypeComponent getComponent(int ordinal) {
		return components.get(ordinal);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#getComponents()
	 */
	@Override
	public DataTypeComponent[] getComponents() {
		return components.toArray(new DataTypeComponent[components.size()]);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#getNumComponents()
	 */
	@Override
	public int getNumComponents() {
		return components.size();
	}

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#add(ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	public DataTypeComponent add(DataType dataType, int length, String componentName,
			String comment) {
		int oldLength = unionLength;
		DataTypeComponent dtc = doAdd(dataType, length, componentName, comment);
		adjustInternalAlignment();
		if (oldLength != unionLength) {
			notifySizeChanged();
		}
		return dtc;
	}

	DataTypeComponent doAdd(DataType dataType, int length, String componentName, String comment) {
		validateDataType(dataType);

		checkAncestry(dataType);

		if (length < 1) {
			throw new IllegalArgumentException("Length must be >= 1!");
		}

		dataType = dataType.clone(getDataTypeManager());

		// TODO Is this the right place to adjust the length?
		int dtLength = dataType.getLength();
		if (dtLength > 0 && dtLength < length) {
			length = dtLength;
		}

		DataTypeComponent dtc = new DataTypeComponentImpl(dataType, this, length, components.size(),
			0, componentName, comment);
		dataType.addParent(this);
		components.add(dtc);
		unionLength = Math.max(unionLength, length);
		return dtc;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.Composite#insert(int, ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length,
			String componentName, String comment) {

		validateDataType(dataType);
		checkAncestry(dataType);

		dataType = dataType.clone(getDataTypeManager());

		// TODO Is this the right place to adjust the length?
		int dtLength = dataType.getLength();
		if (dtLength > 0 && dtLength < length) {
			length = dtLength;
		}

		DataTypeComponent dtc =
			new DataTypeComponentImpl(dataType, this, length, ordinal, 0, componentName, comment);
		dataType.addParent(this);
		shiftOrdinals(ordinal, 1);
		components.add(ordinal, dtc);
		int oldLength = unionLength;
		unionLength = Math.max(unionLength, length);
		adjustInternalAlignment();
		if (oldLength != unionLength) {
			notifySizeChanged();
		}
		return dtc;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public int getLength() {
		if (unionLength == 0) {
			return 1;
		}
		return unionLength;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (getDataTypeManager() == dtm) {
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

	/**
	 * @see ghidra.program.model.data.Composite#delete(int)
	 */
	@Override
	public void delete(int ordinal) {
		int oldLength = unionLength;
		DataTypeComponent dtc = components.remove(ordinal);
		dtc.getDataType().removeParent(this);
		shiftOrdinals(ordinal, -1);
		computeUnionLength();
		adjustInternalAlignment();
		if (oldLength != unionLength) {
			notifySizeChanged();
		}
	}

	@Override
	public void delete(int[] ordinals) {
		for (int ordinal : ordinals) {
			delete(ordinal);
		}
	}

	private void computeUnionLength() {
		unionLength = 0;
		for (int i = 0; i < components.size(); i++) {
			unionLength = Math.max(unionLength, (components.get(i)).getLength());
		}
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#isEquivalent(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null) {
			return false;
		}

		if (dt instanceof Union) {
			Union union = (Union) dt;
			if (isInternallyAligned() != union.isInternallyAligned() ||
				isDefaultAligned() != union.isDefaultAligned() ||
				isMachineAligned() != union.isMachineAligned() ||
				getMinimumAlignment() != union.getMinimumAlignment() ||
				getPackingValue() != union.getPackingValue()) {
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
			DataTypeComponentImpl dtc = (DataTypeComponentImpl) components.get(i);
			dtc.setOrdinal(dtc.getOrdinal() + deltaOrdinal);
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		// TODO I don't think we need to do anything here.
		adjustInternalAlignment();
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeSizeChanged(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeSizeChanged(DataType dt) {
		int oldLength = unionLength;
		unionLength = 0;
		for (int i = 0; i < components.size(); i++) {
			DataTypeComponentImpl dtc = (DataTypeComponentImpl) components.get(i);
			DataType tmpDt = dtc.getDataType();
			int tmpLen = tmpDt.getLength();
			if ((tmpDt.isEquivalent(dt)) && (tmpLen > 0) && (tmpLen != dtc.getLength())) {
				dtc.setLength(tmpLen);
			}
			unionLength = Math.max(unionLength, dtc.getLength());
		}
		adjustInternalAlignment();
		if (oldLength != unionLength) {
			notifySizeChanged();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#dataTypeReplaced(ghidra.program.model.data.DataType, ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		try {
			validateDataType(newDt);
			checkAncestry(newDt);
		}
		catch (Exception e) {
			newDt = DataType.DEFAULT;
		}
		int oldLength = unionLength;
		unionLength = 0;
		boolean changed = false;
		for (int i = 0; i < components.size(); i++) {
			DataTypeComponentImpl dtc = (DataTypeComponentImpl) components.get(i);
			if (dtc.getDataType() == oldDt) {
				oldDt.removeParent(this);
				dtc.setDataType(newDt);
				newDt.addParent(this);
				int len = newDt.getLength();
				if (len > 0) {
					dtc.setLength(len);
				}
				changed = true;
			}
		}
		if (changed) {
			computeUnionLength();
			adjustInternalAlignment();
			if (oldLength != unionLength) {
				notifySizeChanged();
			}
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeDeleted(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeDeleted(DataType dt) {
		boolean didDelete = false;
		for (int i = components.size() - 1; i >= 0; i--) {
			DataTypeComponent dtc = components.get(i);
			if (dtc.getDataType() == dt) {
				dt.removeParent(this);
				components.remove(i);
				shiftOrdinals(i, -1);
				didDelete = true;
			}
		}
		if (didDelete) {
			int oldLength = unionLength;
			computeUnionLength();
			adjustInternalAlignment();
			if (oldLength != unionLength) {
				notifySizeChanged();
			}
		}
	}

	/**
	 * Replaces the internal components of this union with components of the
	 * given union. 
	 * @param dataType the union to get the component information from.
	 * @throws IllegalArgumentException if any of the component data types 
	 * are not allowed to replace a component in this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.
	 */
	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Union)) {
			throw new IllegalArgumentException();
		}
		int oldLength = unionLength;
		doReplaceWith((Union) dataType);
		if (oldLength != unionLength) {
			notifySizeChanged();
		}
	}

	private void doReplaceWith(Union union) {
		Iterator<DataTypeComponent> it = components.iterator();
		while (it.hasNext()) {
			DataTypeComponent dtc = it.next();
			dtc.getDataType().removeParent(this);
		}
		components.clear();

		unionLength = 0;

		DataTypeComponent[] compArray = union.getComponents();
		for (int i = 0; i < compArray.length; i++) {
			DataTypeComponent dtc = compArray[i];
			DataType dt = dtc.getDataType();
			validateDataType(dt);
			dt = dt.clone(getDataTypeManager());
			int dtLength = dt.getLength();
			if (dtLength <= 0) {
				dtLength = dtc.getLength();
			}
			doAdd(dt, dtLength, dtc.getFieldName(), dtc.getComment());
		}
		setDataAlignmentInfo(union);
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeNameChanged(ghidra.program.model.data.DataType, java.lang.String)
	 */
	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
	}

	/**
	 * @see ghidra.program.model.data.DataType#dependsOn(ghidra.program.model.data.DataType)
	 */
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

	public void align(DataOrganization dataOrganization) {
		// TODO Auto-generated method stub
	}

	private void adjustLength() {
		// TODO WHat should we do here?
	}

	@Override
	public int getPackingValue() {
		return packingValue;
	}

	@Override
	public void setPackingValue(int packingValue) {
		this.packingValue = packingValue;
		adjustInternalAlignment();
	}

	@Override
	public void adjustInternalAlignment() {
		adjustLength();
	}

	@Override
	public void realign() {
		adjustInternalAlignment();
	}

}
