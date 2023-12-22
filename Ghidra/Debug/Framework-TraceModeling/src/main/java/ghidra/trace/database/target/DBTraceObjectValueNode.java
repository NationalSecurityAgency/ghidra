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
package ghidra.trace.database.target;

import java.io.IOException;
import java.util.Objects;

import db.DBRecord;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBCachedObjectStoreFactory.RecAddress;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;
import ghidra.util.database.spatial.DBTreeNodeRecord;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceObjectValueNode extends DBTreeNodeRecord<ValueBox> implements ValueBox {
	protected static final byte NODE_TYPE_MASK = 3;
	protected static final int NODE_TYPE_SHIFT = 6;
	protected static final byte NODE_TYPE_CLEAR = (byte) ~(NODE_TYPE_MASK << NODE_TYPE_SHIFT);

	protected static final byte CHILD_COUNT_MASK = 0x3f;
	protected static final int CHILD_COUNT_SHIFT = 0;
	protected static final byte CHILD_COUNT_CLEAR = (byte) ~(CHILD_COUNT_MASK << CHILD_COUNT_SHIFT);

	// Please note the overloaded use of "parent" here:
	static final String PARENT_COLUMN_NAME = "Parent"; // parent in the R*-Tree
	static final String MIN_PARENT_KEY_COLUMN_NAME = "MinParentKey"; // parent in the object tree
	static final String MAX_PARENT_KEY_COLUMN_NAME = "MaxParentKey"; // parent in the object tree
	static final String MIN_CHILD_KEY_COLUMN_NAME = "MinChildKey";
	static final String MAX_CHILD_KEY_COLUMN_NAME = "MaxChildKey";
	static final String MIN_ENTRY_KEY_COLUMN_NAME = "MinEntryKey";
	static final String MAX_ENTRY_KEY_COLUMN_NAME = "MaxEntryKey";
	static final String MIN_SNAP_COLUMN_NAME = "MinSnap";
	static final String MAX_SNAP_COLUMN_NAME = "MaxSnap";
	static final String MIN_SPACE_COLUMN_NAME = "MinSpace";
	static final String MAX_SPACE_COLUMN_NAME = "MaxSpace";
	static final String MIN_ADDRESS_COLUMN_NAME = "MinAddress";
	static final String MAX_ADDRESS_COLUMN_NAME = "MaxAddress";
	static final String TYPE_AND_CHILD_COUNT_COLUMN_NAME = "Type/ChildCount";
	static final String DATA_COUNT_COLUMN_NAME = "DataCount";

	@DBAnnotatedColumn(PARENT_COLUMN_NAME)
	static DBObjectColumn PARENT_COLUMN;
	@DBAnnotatedColumn(MIN_PARENT_KEY_COLUMN_NAME)
	static DBObjectColumn MIN_PARENT_KEY_COLUMN;
	@DBAnnotatedColumn(MAX_PARENT_KEY_COLUMN_NAME)
	static DBObjectColumn MAX_PARENT_KEY_COLUMN;
	@DBAnnotatedColumn(MIN_CHILD_KEY_COLUMN_NAME)
	static DBObjectColumn MIN_CHILD_KEY_COLUMN;
	@DBAnnotatedColumn(MAX_CHILD_KEY_COLUMN_NAME)
	static DBObjectColumn MAX_CHILD_KEY_COLUMN;
	@DBAnnotatedColumn(MIN_ENTRY_KEY_COLUMN_NAME)
	static DBObjectColumn MIN_ENTRY_KEY_COLUMN;
	@DBAnnotatedColumn(MAX_ENTRY_KEY_COLUMN_NAME)
	static DBObjectColumn MAX_ENTRY_KEY_COLUMN;
	@DBAnnotatedColumn(MIN_SNAP_COLUMN_NAME)
	static DBObjectColumn MIN_SNAP_COLUMN;
	@DBAnnotatedColumn(MAX_SNAP_COLUMN_NAME)
	static DBObjectColumn MAX_SNAP_COLUMN;
	@DBAnnotatedColumn(MIN_SPACE_COLUMN_NAME)
	static DBObjectColumn MIN_SPACE_COLUMN;
	@DBAnnotatedColumn(MAX_SPACE_COLUMN_NAME)
	static DBObjectColumn MAX_SPACE_COLUMN;
	@DBAnnotatedColumn(MIN_ADDRESS_COLUMN_NAME)
	static DBObjectColumn MIN_ADDRESS_COLUMN;
	@DBAnnotatedColumn(MAX_ADDRESS_COLUMN_NAME)
	static DBObjectColumn MAX_ADDRESS_COLUMN;
	@DBAnnotatedColumn(TYPE_AND_CHILD_COUNT_COLUMN_NAME)
	static DBObjectColumn TYPE_AND_CHILD_COUNT_COLUMN;
	@DBAnnotatedColumn(DATA_COUNT_COLUMN_NAME)
	static DBObjectColumn DATA_COUNT_COLUMN;

	@DBAnnotatedField(column = PARENT_COLUMN_NAME, indexed = true)
	private long parentKey;
	@DBAnnotatedField(column = MIN_PARENT_KEY_COLUMN_NAME)
	private long minObjParentKey;
	@DBAnnotatedField(column = MAX_PARENT_KEY_COLUMN_NAME)
	private long maxObjParentKey;
	@DBAnnotatedField(column = MIN_CHILD_KEY_COLUMN_NAME)
	private long minObjChildKey;
	@DBAnnotatedField(column = MAX_CHILD_KEY_COLUMN_NAME)
	private long maxObjChildKey;
	@DBAnnotatedField(column = MIN_ENTRY_KEY_COLUMN_NAME)
	private String minEntryKey;
	@DBAnnotatedField(column = MAX_ENTRY_KEY_COLUMN_NAME)
	private String maxEntryKey;
	@DBAnnotatedField(column = MIN_SNAP_COLUMN_NAME)
	private long minSnap;
	@DBAnnotatedField(column = MAX_SNAP_COLUMN_NAME)
	private long maxSnap;
	@DBAnnotatedField(column = MIN_SPACE_COLUMN_NAME)
	private int minSpace;
	@DBAnnotatedField(column = MAX_SPACE_COLUMN_NAME)
	private int maxSpace;
	@DBAnnotatedField(column = MIN_ADDRESS_COLUMN_NAME)
	private long minAddress;
	@DBAnnotatedField(column = MAX_ADDRESS_COLUMN_NAME)
	private long maxAddress;
	@DBAnnotatedField(column = TYPE_AND_CHILD_COUNT_COLUMN_NAME)
	private byte typeAndChildCount;
	@DBAnnotatedField(column = DATA_COUNT_COLUMN_NAME)
	private int dataCount;

	protected final DBTraceObjectValueRStarTree tree;

	private ValueTriple lCorner;
	private ValueTriple uCorner;

	public DBTraceObjectValueNode(DBTraceObjectValueRStarTree tree, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.tree = tree;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}
		lCorner = new ValueTriple(minObjParentKey, minObjChildKey, minEntryKey, minSnap,
			new RecAddress(minSpace, minAddress));
		uCorner = new ValueTriple(maxObjParentKey, maxObjChildKey, maxEntryKey, maxSnap,
			new RecAddress(maxSpace, maxAddress));
	}

	@Override
	public ValueTriple lCorner() {
		return Objects.requireNonNull(lCorner);
	}

	@Override
	public ValueTriple uCorner() {
		return Objects.requireNonNull(uCorner);
	}

	@Override
	protected NodeType getType() {
		return NodeType.VALUES.get((typeAndChildCount >> NODE_TYPE_SHIFT) & NODE_TYPE_MASK);
	}

	@Override
	protected void setType(NodeType type) {
		typeAndChildCount =
			(byte) (typeAndChildCount & NODE_TYPE_CLEAR | (type.ordinal() << NODE_TYPE_SHIFT));
		update(TYPE_AND_CHILD_COUNT_COLUMN);
	}

	@Override
	protected int getChildCount() {
		return (typeAndChildCount >> CHILD_COUNT_SHIFT) & CHILD_COUNT_MASK;
	}

	@Override
	protected void setChildCount(int childCount) {
		assert (childCount & CHILD_COUNT_MASK) == childCount;
		typeAndChildCount =
			(byte) (typeAndChildCount & CHILD_COUNT_CLEAR | (childCount << CHILD_COUNT_SHIFT));
		update(TYPE_AND_CHILD_COUNT_COLUMN);
	}

	@Override
	protected int getDataCount() {
		return dataCount;
	}

	@Override
	protected void setDataCount(int dataCount) {
		this.dataCount = dataCount;
		update(DATA_COUNT_COLUMN);
	}

	@Override
	public ValueBox getShape() {
		return this;
	}

	@Override
	public void setShape(ValueBox shape) {
		minObjParentKey = shape.lCorner().parentKey();
		maxObjParentKey = shape.uCorner().parentKey();
		minObjChildKey = shape.lCorner().childKey();
		maxObjChildKey = shape.uCorner().childKey();
		minEntryKey = shape.lCorner().entryKey();
		maxEntryKey = shape.uCorner().entryKey();
		minSnap = shape.lCorner().snap();
		maxSnap = shape.uCorner().snap();
		minSpace = shape.lCorner().address().spaceId();
		maxSpace = shape.uCorner().address().spaceId();
		minAddress = shape.lCorner().address().offset();
		maxAddress = shape.uCorner().address().offset();
		update(
			MIN_PARENT_KEY_COLUMN, MAX_PARENT_KEY_COLUMN,
			MIN_CHILD_KEY_COLUMN, MAX_CHILD_KEY_COLUMN,
			MIN_ENTRY_KEY_COLUMN, MAX_ENTRY_KEY_COLUMN,
			MIN_SNAP_COLUMN, MAX_SNAP_COLUMN,
			MIN_SPACE_COLUMN, MAX_SPACE_COLUMN,
			MIN_ADDRESS_COLUMN, MAX_ADDRESS_COLUMN);

		lCorner = shape.lCorner();
		uCorner = shape.uCorner();
	}

	@Override
	public ValueBox getBounds() {
		return this;
	}

	@Override
	public long getParentKey() {
		return parentKey;
	}

	@Override
	public void setParentKey(long parentKey) {
		this.parentKey = parentKey;
		update(PARENT_COLUMN);
	}
}
