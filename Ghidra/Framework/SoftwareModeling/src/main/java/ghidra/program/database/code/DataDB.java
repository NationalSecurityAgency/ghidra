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
package ghidra.program.database.code;

import java.util.*;

import db.DBRecord;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.Msg;

/**
 * Database implementation for the Data interface.
 *
 * NOTE!! DataComponents only have a unique key within its parent Struct/Array.  This places a constraint on
 * the use of the key field and getKey() method on the underlying classes CodeUnitDB and DataDB.
 * The CodeUnit key should only be used for managing an object cache.  The addr field should be used within
 * this class instead of the key field which represents an "index in parent" for data components which are
 * cached separately.
 */
class DataDB extends CodeUnitDB implements Data {

	protected DataType dataType;
	protected DataType baseDataType;

	protected int level = 0;
	protected DataTypeManagerDB dataMgr;
	protected Settings defaultSettings;

	private Boolean hasMutabilitySetting;

	private static final int[] EMPTY_PATH = new int[0];

	private DBObjectCache<DataDB> componentCache = null;// data components are keyed on index in parent (i.e., ordinal)

	DataDB(CodeManager codeMgr, DBObjectCache<? extends CodeUnitDB> codeUnitCache, long cacheKey,
			Address address, long addr, DataType dataType) {

		super(codeMgr, codeUnitCache, cacheKey, address, addr,
			dataType == null ? 1 : dataType.getLength());
		if (dataType == null) {
			dataType = DataType.DEFAULT;
		}
		this.dataType = dataType;
		dataMgr = program.getDataTypeManager();

		baseDataType = getBaseDataType(dataType);

		defaultSettings = dataType.getDefaultSettings();
		computeLength();
		if (length < 0) {
			Msg.error(this, " bad bad");
		}
	}

	protected static DataType getBaseDataType(DataType dataType) {
		DataType dt = dataType;
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		return dt;
	}

	@Override
	protected boolean refresh(DBRecord record) {
		if (componentCache != null) {
			componentCache.invalidate();
		}
		hasMutabilitySetting = null;
		return super.refresh(record);
	}

	@Override
	protected boolean hasBeenDeleted(DBRecord rec) {
		if (dataType == DataType.DEFAULT) {
			return rec != null || !codeMgr.isUndefined(address, addr);
		}
		DataType dt;
		if (rec != null) {
			// ensure that record provided corresponds to a DataDB record
			// since following an undo/redo the record could correspond to
			// a different type of code unit (hopefully with a different record schema)
			if (!rec.hasSameSchema(DataDBAdapter.DATA_SCHEMA)) {
				return true;
			}
			dt = codeMgr.getDataType(rec);
			if (dt == null) {
				Msg.error(this, "Data found but datatype missing at " + address);
			}
		}
		else {
			dt = codeMgr.getDataType(addr);
		}
		if (dt == null) {
			return true;
		}
		dataType = dt;
		baseDataType = getBaseDataType(dataType);
		defaultSettings = dataType.getDefaultSettings();
		computeLength();
		return false;
	}

	private void computeLength() {
		length = dataType.getLength();
		if (length < 1) {
			length = codeMgr.getLength(address);
		}
		if (length < 1) {
			if (baseDataType instanceof Pointer) {
				length = address.getPointerSize();
			}
			else {
				length = 1;
			}
		}

		// FIXME Trying to get Data to display for External.
		if (address.isExternalAddress()) { // FIXME
			return; // FIXME
		} // FIXME

		Memory mem = program.getMemory();
		Address endAddress = null;
		boolean noEndAddr = false;
		try {
			endAddress = address.addNoWrap(length - 1);
		}
		catch (AddressOverflowException ex) {
			noEndAddr = true;
		}

		if (noEndAddr || (!mem.contains(address, endAddress))) {
			MemoryBlock block = mem.getBlock(address);
			if (block != null) {
				endAddress = block.getEnd();
				length = (int) endAddress.subtract(address) + 1;
			}
			else {
				length = 1; // ?? what should this be?
			}
		}

		Address nextAddr = codeMgr.getDefinedAddressAfter(address);
		if ((nextAddr != null) && nextAddr.compareTo(endAddress) <= 0) {
			length = (int) nextAddr.subtract(address);
		}
		bytes = null;
	}

	@Override
	public void addValueReference(Address refAddr, RefType type) {
		refreshIfNeeded();
		refMgr.addMemoryReference(address, refAddr, type, SourceType.USER_DEFINED,
			CodeManager.DATA_OP_INDEX);
	}

	@Override
	public void removeValueReference(Address refAddr) {
		removeOperandReference(CodeManager.DATA_OP_INDEX, refAddr);
	}

	@Override
	public Data getComponent(int index) {
		lock.acquire();
		try {

			checkIsValid();

			if (index < 0 || index >= getNumComponents()) {
				return null;
			}

			if (componentCache == null) {
				componentCache = new DBObjectCache<>(1);
			}
			else {
				Data data = componentCache.get(index);
				if (data != null) {
					return data;
				}
			}

			AddressMap addressMap = codeMgr.getAddressMap();

			if (baseDataType instanceof Array) {
				Array array = (Array) baseDataType;
				int elementLength = array.getElementLength();
				Address componentAddr = address.add(index * elementLength);
				return new DataComponent(codeMgr, componentCache, componentAddr,
					addressMap.getKey(componentAddr, false), this, array.getDataType(), index,
					index * elementLength, elementLength);
			}
			if (baseDataType instanceof Composite) {
				Composite struct = (Composite) baseDataType;
				DataTypeComponent dtc = struct.getComponent(index);
				Address componentAddr = address.add(dtc.getOffset());
				return new DataComponent(codeMgr, componentCache, componentAddr,
					addressMap.getKey(componentAddr, false), this, dtc);

			}
			if (baseDataType instanceof DynamicDataType) {
				DynamicDataType ddt = (DynamicDataType) baseDataType;
				DataTypeComponent dtc = ddt.getComponent(index, this);
				Address componentAddr = address.add(dtc.getOffset());
				return new DataComponent(codeMgr, componentCache, componentAddr,
					addressMap.getKey(componentAddr, false), this, dtc);
			}
			Msg.error(this,
				"Unsupported composite data type class: " + baseDataType.getClass().getName());
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Address getAddress(int opIndex) {
		if (opIndex == 0) {
			Object obj = getValue();
			if (obj instanceof Address) {
				return (Address) obj;
			}
		}
		return null;
	}

	/**
	 * Provide default formatted string representation of this instruction.
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String valueRepresentation = getDefaultValueRepresentation();
		String mnemonicString = getMnemonicString();
		if (valueRepresentation == null) {
			return mnemonicString;
		}
		return mnemonicString + " " + valueRepresentation;
	}

	@Override
	public String getDefaultValueRepresentation() {
		lock.acquire();
		try {
			checkIsValid();
			return dataType.getRepresentation(this, this, length);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getMnemonicString() {
		lock.acquire();
		try {
			checkIsValid();
			return dataType.getMnemonic(this);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getNumOperands() {
		return 1;
	}

	@Override
	public Scalar getScalar(int opIndex) {
		if (opIndex == 0) {
			Object obj = getValue();
			if (obj instanceof Scalar) {
				return (Scalar) obj;
			}
			else if (obj instanceof Address) {
				Address addrObj = (Address) obj;
				long offset = addrObj.getAddressableWordOffset();
				return new Scalar(addrObj.getAddressSpace().getPointerSize() * 8, offset, false);
			}
		}
		return null;
	}

	@Override
	public DataType getBaseDataType() {
		return baseDataType;
	}

	private <T extends SettingsDefinition> T getSettingsDefinition(
			Class<T> settingsDefinitionClass) {
		DataType dt = baseDataType;
		for (SettingsDefinition def : dt.getSettingsDefinitions()) {
			if (settingsDefinitionClass.isAssignableFrom(def.getClass())) {
				return settingsDefinitionClass.cast(def);
			}
		}
		return null;
	}

	private boolean hasMutability(int mutabilityType) {
		Boolean hasSetting = hasMutabilitySetting;
		if (hasSetting != null && !hasSetting) {
			return mutabilityType == MutabilitySettingsDefinition.NORMAL;
		}
		lock.acquire();
		try {
			checkIsValid();
			MutabilitySettingsDefinition def =
				getSettingsDefinition(MutabilitySettingsDefinition.class);
			if (def != null) {
				hasMutabilitySetting = true;
				return def.getChoice(this) == mutabilityType;
			}
			hasMutabilitySetting = false;
		}
		finally {
			lock.release();
		}
		return false;
	}

	@Override
	public boolean isConstant() {
		return hasMutability(MutabilitySettingsDefinition.CONSTANT);
	}

	@Override
	public boolean isVolatile() {
		return hasMutability(MutabilitySettingsDefinition.VOLATILE);
	}

	@Override
	public void clearSetting(String name) {
		refreshIfNeeded();
		Address cuAddr = getDataSettingsAddress();
		if (dataMgr.clearSetting(cuAddr, name)) {
			changeMgr.setChanged(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED, cuAddr, cuAddr, null,
				null);
		}
	}

	@Override
	public byte[] getByteArray(String name) {
		refreshIfNeeded();
		byte[] tempBytes = dataMgr.getByteSettingsValue(getDataSettingsAddress(), name);
		if (tempBytes == null && defaultSettings != null) {
			tempBytes = defaultSettings.getByteArray(name);
		}
		return tempBytes;
	}

	@Override
	public Long getLong(String name) {
		refreshIfNeeded();
		Long value = dataMgr.getLongSettingsValue(getDataSettingsAddress(), name);
		if (value == null && defaultSettings != null) {
			value = defaultSettings.getLong(name);
		}
		return value;
	}

	@Override
	public String[] getNames() {
		refreshIfNeeded();
		return dataMgr.getNames(getDataSettingsAddress());
	}

	@Override
	public String getString(String name) {
		refreshIfNeeded();
		String value = dataMgr.getStringSettingsValue(getDataSettingsAddress(), name);
		if (value == null && defaultSettings != null) {
			value = defaultSettings.getString(name);
		}
		return value;
	}

	@Override
	public Object getValue(String name) {
		refreshIfNeeded();
		Object value = dataMgr.getSettings(getDataSettingsAddress(), name);
		if (value == null && defaultSettings != null) {
			value = defaultSettings.getValue(name);
		}
		return value;
	}

	@Override
	public void setByteArray(String name, byte[] value) {
		refreshIfNeeded();
		Address cuAddr = getDataSettingsAddress();
		if (dataMgr.setByteSettingsValue(cuAddr, name, value)) {
			changeMgr.setChanged(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED, cuAddr, cuAddr, null,
				null);
		}
	}

	@Override
	public void setLong(String name, long value) {
		refreshIfNeeded();
		Address cuAddr = getDataSettingsAddress();
		if (dataMgr.setLongSettingsValue(cuAddr, name, value)) {
			changeMgr.setChanged(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED, cuAddr, cuAddr, null,
				null);
		}
	}

	@Override
	public void setString(String name, String value) {
		refreshIfNeeded();
		Address cuAddr = getDataSettingsAddress();
		if (dataMgr.setStringSettingsValue(cuAddr, name, value)) {
			changeMgr.setChanged(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED, cuAddr, cuAddr, null,
				null);
		}
	}

	@Override
	public void setValue(String name, Object value) {
		refreshIfNeeded();
		Address cuAddr = getDataSettingsAddress();
		if (dataMgr.setSettings(cuAddr, name, value)) {
			changeMgr.setChanged(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED, cuAddr, cuAddr, null,
				null);
		}
	}

	@Override
	public Data getComponent(int[] componentPath) {
		lock.acquire();
		try {
			if (componentPath == null || componentPath.length <= level) {
				return this;
			}
			Data component = getComponent(componentPath[level]);
			return (component == null ? null : component.getComponent(componentPath));
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getComment(int commentType) {
		Data child = getComponentContaining(0);
		if (child != null) {
			// avoid caching issue by maintaining comment at lowest point in data path
			return child.getComment(commentType);
		}
		return super.getComment(commentType);
	}

	@Override
	public void setComment(int commentType, String comment) {
		Data child = getComponentContaining(0);
		if (child != null) {
			// avoid caching issue by maintaining comment at lowest point in data path
			child.setComment(commentType, comment);
		}
		else {
			super.setComment(commentType, comment);
		}
	}

	@Deprecated
	@Override
	public Data getComponentAt(int offset) {
		return getComponentContaining(offset);
	}

	@Override
	public Data getComponentContaining(int offset) {
		lock.acquire();
		try {
			checkIsValid();
			if (offset < 0 || offset > length) {
				return null;
			}

			if (baseDataType instanceof Array) {
				Array array = (Array) baseDataType;
				int elementLength = array.getElementLength();
				int index = offset / elementLength;
				return getComponent(index);
			}
			else if (baseDataType instanceof Structure) {
				Structure struct = (Structure) baseDataType;
				DataTypeComponent dtc = struct.getComponentContaining(offset);
				return (dtc != null) ? getComponent(dtc.getOrdinal()) : null;
			}
			else if (baseDataType instanceof DynamicDataType) {
				DynamicDataType ddt = (DynamicDataType) baseDataType;
				DataTypeComponent dtc = ddt.getComponentAt(offset, this);
				return (dtc != null) ? getComponent(dtc.getOrdinal()) : null;
			}
			else if (baseDataType instanceof Union) {
				// TODO: Returning anything is potentially bad
				//return getComponent(0);
			}
			return null;
		}
		finally {
			lock.release();
		}

	}

	@Override
	public List<Data> getComponentsContaining(int offset) {
		lock.acquire();
		try {
			checkIsValid();
			if (offset < 0 || offset >= length) {
				return null;
			}
			if (baseDataType instanceof Array) {
				Array array = (Array) baseDataType;
				int elementLength = array.getElementLength();
				int index = offset / elementLength;
				return Collections.singletonList(getComponent(index));
			}
			else if (baseDataType instanceof Structure) {
				Structure struct = (Structure) baseDataType;
				List<Data> result = new ArrayList<>();
				for (DataTypeComponent dtc : struct.getComponentsContaining(offset)) {
					result.add(getComponent(dtc.getOrdinal()));
				}
				return result;
			}
			else if (baseDataType instanceof DynamicDataType) {
				DynamicDataType ddt = (DynamicDataType) baseDataType;
				DataTypeComponent dtc = ddt.getComponentAt(offset, this);
				List<Data> result = new ArrayList<>();
				// Logic handles overlapping bit-fields
				// Include if offset is contained within bounds of component
				while (dtc != null && (offset >= dtc.getOffset()) &&
					(offset < (dtc.getOffset() + dtc.getLength()))) {
					int ordinal = dtc.getOrdinal();
					result.add(getComponent(ordinal++));
					dtc = ordinal < ddt.getNumComponents(this) ? ddt.getComponent(ordinal, this)
							: null;
				}
				return result;
			}
			else if (baseDataType instanceof Union) {
				Union union = (Union) baseDataType;
				List<Data> result = new ArrayList<>();
				for (DataTypeComponent dtc : union.getComponents()) {
					if (offset < dtc.getLength()) {
						result.add(getComponent(dtc.getOrdinal()));
					}
				}
				return result;
			}
			return Collections.emptyList();
		}
		finally {
			lock.release();
		}

	}

	@Override
	public int getComponentIndex() {
		return -1;
	}

	@Override
	public int getComponentLevel() {
		return level;
	}

	@Override
	public int[] getComponentPath() {
		return EMPTY_PATH;
	}

	@Override
	public String getComponentPathName() {
		return null;
	}

//	public Data[] getComponents() {
//		lock.acquire();
//		try {
//	      	checkIsValid();
//	        if (length < dataType.getLength()) {
//	            return null;
//	        }
//	        Data[] retData = EMPTY_COMPONENTS;
//	        if (baseDataType instanceof Composite) {
//				Composite composite = (Composite)baseDataType;
//				int n = composite.getNumComponents();
//				retData = new Data[n];
//				for(int i=0;i<n;i++) {
//					retData[i] = getComponent(i);
//				}
//	        }
//			else if (baseDataType instanceof Array) {
//				Array array = (Array)baseDataType;
//				int n = array.getNumElements();
//				retData = new Data[n];
//				for(int i=0;i<n;i++) {
//					retData[i] = getComponent(i);
//				}
//			}
//			else if (baseDataType instanceof DynamicDataType) {
//				DynamicDataType ddt = (DynamicDataType)baseDataType;
//				int n = ddt.getNumComponents(this);
//				retData = new Data[n];
//				for(int i=0;i<n;i++) {
//					retData[i] = getComponent(i);
//				}
//			}
//			return retData;
//		}
//		finally {
//			lock.release();
//		}
//	}

	@Override
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public String getFieldName() {
		return null;
	}

	@Override
	public int getNumComponents() {
		lock.acquire();
		try {
			checkIsValid();
			if (length < dataType.getLength()) {
				return -1;
			}
			if (baseDataType instanceof Composite) {
				return ((Composite) baseDataType).getNumComponents();
			}
			else if (baseDataType instanceof Array) {
				return ((Array) baseDataType).getNumElements();
			}
			else if (baseDataType instanceof DynamicDataType) {
				try {
					return ((DynamicDataType) baseDataType).getNumComponents(this);
				}
				catch (Throwable t) {
					//Msg.error(this,
					//	"Data type error (" + baseDataType.getName() + "): " + t.getMessage(), t);
					return 0;
				}
			}
			return 0;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Data getParent() {
		return null;
	}

	@Override
	public int getParentOffset() {
		return 0;
	}

	@Override
	public String getPathName() {
		refreshIfNeeded();
		Address cuAddress = address;
		SymbolTable st = program.getSymbolTable();
		Symbol symbol = st.getPrimarySymbol(cuAddress);
		if (symbol == null) {
			return SymbolUtilities.getDynamicName(program, cuAddress);
		}
		return symbol.getName();
	}

	@Override
	public Data getPrimitiveAt(int offset) {
		lock.acquire();
		try {
			checkIsValid();
			if (offset < 0 || offset >= length) {
				return null;
			}
			Data dc = getComponentContaining(offset);
			if (dc == null || dc == this) {
				return this;
			}
			return dc.getPrimitiveAt(offset - dc.getParentOffset());
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Data getRoot() {
		return this;
	}

	@Override
	public int getRootOffset() {
		return 0;
	}

	@Override
	public Object getValue() {
		lock.acquire();
		try {
			checkIsValid();
			return baseDataType.getValue(this, this, length);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Class<?> getValueClass() {
		DataType dt = getBaseDataType();
		if (dt != null) {
			return dt.getValueClass(this);
		}
		return null;
	}

	@Override
	public boolean hasStringValue() {
		return String.class.equals(getValueClass());
	}

	@Override
	public String getDefaultLabelPrefix(DataTypeDisplayOptions options) {
		if (dataType == DataType.DEFAULT) {
			return null;
		}
		if (options == null) {
			options = DataTypeDisplayOptions.DEFAULT;
		}
		return dataType.getDefaultLabelPrefix(this, this, length, options);
	}

	@Override
	public Reference[] getValueReferences() {
		return getOperandReferences(CodeManager.DATA_OP_INDEX);
	}

	@Override
	public boolean isArray() {
		return baseDataType instanceof Array;
	}

	@Override
	public boolean isDefined() {
		return !(dataType instanceof DefaultDataType);
	}

	@Override
	public boolean isPointer() {
		return baseDataType instanceof Pointer;
	}

	@Override
	public boolean isStructure() {
		return baseDataType instanceof Structure;
	}

	@Override
	public boolean isDynamic() {
		return baseDataType instanceof DynamicDataType;
	}

	@Override
	public boolean isUnion() {
		return baseDataType instanceof Union;
	}

	@Override
	public void clearAllSettings() {
		refreshIfNeeded();
		Address cuAddr = getDataSettingsAddress();
		dataMgr.clearAllSettings(cuAddr);
		changeMgr.setChanged(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED, cuAddr, cuAddr, null,
			null);
	}

	@Override
	public boolean isEmpty() {
		refreshIfNeeded();
		return dataMgr.isEmptySetting(getDataSettingsAddress());
	}

	@Override
	public Reference[] getReferencesFrom() {
		ArrayList<Reference> list = new ArrayList<>();

		AddressSet set = new AddressSet(this.getMinAddress(), this.getMaxAddress());
		AddressIterator iter = refMgr.getReferenceSourceIterator(set, true);
		while (iter.hasNext()) {
			Address fromAddress = iter.next();
			Reference[] refs = refMgr.getReferencesFrom(fromAddress);
			for (Reference element : refs) {
				list.add(element);
			}
		}
		return list.toArray(new Reference[list.size()]);
	}

	@Override
	public Settings getDefaultSettings() {
		return defaultSettings;
	}

	protected Address getDataSettingsAddress() {
		return address;
	}
}
