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

import java.lang.ref.WeakReference;
import java.util.*;
import java.util.function.Consumer;

import ghidra.docking.settings.*;
import ghidra.util.*;

/**
 * Base implementation for dataTypes.
 * 
 * NOTE: Settings are immutable when a DataTypeManager has not been specified (i.e., null).
 */
public abstract class DataTypeImpl extends AbstractDataType {

	private final static SettingsDefinition[] EMPTY_DEFINITIONS = new SettingsDefinition[0];

	// NOTE: Modification of default settings on Impl datatypes is generally blocked
	// with the exception of TypeDef's and BuiltInDataType which have had a suitable
	// defaultSettings implementation established by its DataTypeManager.
	protected Settings defaultSettings;

	private Integer alignedLength;

	private List<WeakReference<DataType>> parentList;
	private UniversalID universalID;
	private SourceArchive sourceArchive;
	private long lastChangeTime;
	private long lastChangeTimeInSourceArchive;

	protected DataTypeImpl(CategoryPath path, String name, DataTypeManager dataMgr) {
		this(path, name, null, null, System.currentTimeMillis(), NO_LAST_CHANGE_TIME, dataMgr);
	}

	DataTypeImpl(CategoryPath path, String name, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dataMgr) {
		super(path, name, dataMgr);
		defaultSettings = SettingsImpl.NO_SETTINGS;
		parentList = new ArrayList<>();
		this.universalID = universalID == null ? UniversalIdGenerator.nextID() : universalID;
		this.sourceArchive = sourceArchive;
		this.lastChangeTime = lastChangeTime;
		this.lastChangeTimeInSourceArchive = lastChangeTimeInSourceArchive;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return null;
	}

	@Override
	public Settings getDefaultSettings() {
		return defaultSettings;
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return EMPTY_DEFINITIONS;
	}

	/**
	 * Check if the name is a valid name for a data type
	 *
	 * @param checkedName name to check
	 *
	 * @throws InvalidNameException if the name is invalid
	 */
	void checkValidName(String checkedName) throws InvalidNameException {
		if (!DataUtilities.isValidDataTypeName(checkedName)) {
			throw new InvalidNameException("Invalid Name: " + checkedName);
		}
	}

	@Override
	public String getPathName() {
		return getDataTypePath().getPath();
	}

	/**
	 * Return the aligned-length for a fixed length datatype.  This is intended to produce a
	 * result consistent with the C/C++ {@code sizeof(type)} operation.  Use of this method
	 * with {@link TypeDef} is not allowed.
	 * Whereas {@link #getLength()} corresponds to the raw type size which may be moved into
	 * a smaller register/varnode.  Example: this frequently occurs with encoded floating-point
	 * data such as a 10-byte/80-bit encoding which is stored in memory as 12 or 16-bytes in order
	 * to maintain memory alignment constraints.
	 * @param dataType datatype
	 * @return aligned-length or -1 if not a fixed-length datatype
	 */
	private static int computeAlignedLength(DataType dataType) {
		if ((dataType instanceof TypeDef) || (dataType instanceof Composite) ||
			(dataType instanceof Array)) {
			// Typedefs must defer to base datatype for aligned-length determination
			throw new UnsupportedOperationException();
		}
		int len = dataType.getLength();
		if (len <= 0 || (dataType instanceof Pointer)) {
			return len;
		}
		int align = dataType.getDataOrganization().getSizeAlignment(len);
		int mod = len % align;
		if (mod != 0) {
			len += (align - mod);
		}
		return len;
	}

	@Override
	public int getAlignedLength() {
		if (alignedLength == null) {
			alignedLength = computeAlignedLength(this);
		}
		return alignedLength;
	}

	@Override
	public int getAlignment() {
		int length = getLength();
		if (length < 0) {
			return 1;
		}
		return getDataOrganization().getAlignment(this);
	}

	@Override
	public void addParent(DataType dt) {
		parentList.add(new WeakReference<>(dt));
	}

	@Override
	public void removeParent(DataType dt) {
		Iterator<WeakReference<DataType>> iterator = parentList.iterator();
		while (iterator.hasNext()) {
			WeakReference<DataType> ref = iterator.next();
			DataType dataType = ref.get();
			if (dataType == null) {
				iterator.remove();
			}
			else if (dt == dataType) {
				iterator.remove();
				break;
			}
		}
	}

	@Override
	public Collection<DataType> getParents() {
		List<DataType> parents = new ArrayList<>();
		Iterator<WeakReference<DataType>> iterator = parentList.iterator();
		while (iterator.hasNext()) {
			WeakReference<DataType> ref = iterator.next();
			DataType dataType = ref.get();
			if (dataType == null) {
				iterator.remove();
			}
			else {
				parents.add(dataType);
			}
		}
		return parents;
	}

	/**
	 * Notify all parents that the size of this datatype has changed or
	 * other significant change that may affect a parent containing this
	 * datatype.
	 */
	protected void notifySizeChanged() {
		notifyParents(dt -> dt.dataTypeSizeChanged(this));
	}

	/**
	 * Notify all parents that this datatype's alignment has changed
	 */
	protected void notifyAlignmentChanged() {
		notifyParents(dt -> dt.dataTypeAlignmentChanged(this));
	}

	/**
	 * Notify all parents that this datatype's name has changed
	 *
	 * @param oldName
	 */
	protected void notifyNameChanged(String oldName) {
		notifyParents(dt -> dt.dataTypeNameChanged(this, oldName));
	}

	/**
	 * Notify all parents that this datatype has been deleted
	 */
	protected void notifyDeleted() {
		notifyParents(dt -> dt.dataTypeDeleted(this));
	}

	/**
	 * Notify any parents that I have been replaced.
	 * @param replacement replacement data type
	 */
	protected void notifyReplaced(DataType replacement) {
		notifyParents(dt -> dt.dataTypeReplaced(this, replacement));
	}

	protected final void notifyParents(Consumer<DataType> consumer) {
		Iterator<WeakReference<DataType>> iterator = parentList.iterator();
		while (iterator.hasNext()) {
			WeakReference<DataType> ref = iterator.next();
			DataType dataType = ref.get();
			if (dataType == null) {
				iterator.remove();
			}
			else {
				consumer.accept(dataType);
			}
		}
	}

	@Override
	public long getLastChangeTime() {
		return lastChangeTime;
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		return lastChangeTimeInSourceArchive;
	}

	@Override
	public SourceArchive getSourceArchive() {
		return sourceArchive;
	}

	@Override
	public void setSourceArchive(SourceArchive archive) {
		this.sourceArchive = archive;
	}

	@Override
	public UniversalID getUniversalID() {
		return universalID;
	}

	@Override
	public void replaceWith(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		this.lastChangeTime = lastChangeTime;
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		this.lastChangeTimeInSourceArchive = lastChangeTimeInSourceArchive;
	}

	/**
	 * Sets a String briefly describing this DataType.
	 * <br>If a data type that extends this class wants to allow the description to be changed,
	 * then it must override this method.
	 * @param description a one-liner describing this DataType.
	 * @throws UnsupportedOperationException if the description is not allowed to be set for this data type.
	 */
	@Override
	public void setDescription(String description) throws UnsupportedOperationException {
		throw new UnsupportedOperationException(
			getClass().getName() + " doesn't allow the description to be changed.");
	}

	@Override
	public int hashCode() {
		// Note: this works because the DTMs have to be equal and there can be only one DT with
		//       the same name and category path
		return getName().hashCode();
	}

	@Override
	public final boolean equals(Object obj) {
		if (!(obj instanceof DataType)) {
			return false;
		}
		DataType otherDt = (DataType) obj;
		return otherDt.getDataTypeManager() == getDataTypeManager() &&
			categoryPath.equals(otherDt.getCategoryPath()) && name.equals(otherDt.getName()) &&
			isEquivalent(otherDt);
	}

}
