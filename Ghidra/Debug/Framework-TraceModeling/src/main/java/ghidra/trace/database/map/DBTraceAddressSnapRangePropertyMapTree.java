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
package ghidra.trace.database.map;

import java.io.IOException;
import java.util.*;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap.DBTraceAddressSnapRangePropertyMapDataFactory;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.*;
import ghidra.trace.model.*;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.database.spatial.DBTreeDataRecord;
import ghidra.util.database.spatial.DBTreeNodeRecord;
import ghidra.util.database.spatial.rect.*;
import ghidra.util.exception.VersionException;

public class DBTraceAddressSnapRangePropertyMapTree<T, DR extends AbstractDBTraceAddressSnapRangePropertyMapData<T>>
		extends Abstract2DRStarTree< //
				Address, Long, //
				TraceAddressSnapRange, DR, // 
				TraceAddressSnapRange, DBTraceAddressSnapRangePropertyMapNode, //
				T, TraceAddressSnapRangeQuery> {

	protected static final int MAX_CHILDREN = 50;

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceAddressSnapRangePropertyMapNode
			extends DBTreeNodeRecord<TraceAddressSnapRange> implements TraceAddressSnapRange {
		protected static final byte NODE_TYPE_MASK = 3;
		protected static final int NODE_TYPE_SHIFT = 6;
		protected static final byte NODE_TYPE_CLEAR = (byte) ~(NODE_TYPE_MASK << NODE_TYPE_SHIFT);

		protected static final byte CHILD_COUNT_MASK = 0x3f;
		protected static final int CHILD_COUNT_SHIFT = 0;
		protected static final byte CHILD_COUNT_CLEAR =
			(byte) ~(CHILD_COUNT_MASK << CHILD_COUNT_SHIFT);

		static final String PARENT_COLUMN_NAME = "Parent";
		static final String MIN_ADDRESS_COLUMN_NAME = "MinAddress";
		static final String MAX_ADDRESS_COLUMN_NAME = "MaxAddress";
		static final String MIN_SNAP_COLUMN_NAME = "MinSnap";
		static final String MAX_SNAP_COLUMN_NAME = "MaxSnap";
		static final String TYPE_AND_CHILD_COUNT_COLUMN_NAME = "Type/ChildCount";
		static final String DATA_COUNT_COLUMN_NAME = "DataCount";

		@DBAnnotatedColumn(PARENT_COLUMN_NAME)
		static DBObjectColumn PARENT_COLUMN;
		@DBAnnotatedColumn(MIN_ADDRESS_COLUMN_NAME)
		static DBObjectColumn MIN_ADDRESS_COLUMN;
		@DBAnnotatedColumn(MAX_ADDRESS_COLUMN_NAME)
		static DBObjectColumn MAX_ADDRESS_COLUMN;
		@DBAnnotatedColumn(MIN_SNAP_COLUMN_NAME)
		static DBObjectColumn MIN_SNAP_COLUMN;
		@DBAnnotatedColumn(MAX_SNAP_COLUMN_NAME)
		static DBObjectColumn MAX_SNAP_COLUMN;
		@DBAnnotatedColumn(TYPE_AND_CHILD_COUNT_COLUMN_NAME)
		static DBObjectColumn TYPE_AND_CHILD_COUNT_COLUMN;
		@DBAnnotatedColumn(DATA_COUNT_COLUMN_NAME)
		static DBObjectColumn DATA_COUNT_COLUMN;

		@DBAnnotatedField(column = PARENT_COLUMN_NAME, indexed = true)
		private long parentKey;
		@DBAnnotatedField(column = MIN_ADDRESS_COLUMN_NAME)
		private long minOffset;
		@DBAnnotatedField(column = MAX_ADDRESS_COLUMN_NAME)
		private long maxOffset;
		@DBAnnotatedField(column = MIN_SNAP_COLUMN_NAME)
		private long minSnap;
		@DBAnnotatedField(column = MAX_SNAP_COLUMN_NAME)
		private long maxSnap;
		@DBAnnotatedField(column = TYPE_AND_CHILD_COUNT_COLUMN_NAME)
		private byte typeAndChildCount;
		@DBAnnotatedField(column = DATA_COUNT_COLUMN_NAME)
		private int dataCount;

		protected final DBTraceAddressSnapRangePropertyMapTree<?, ?> tree;

		private AddressRange range;
		private Range<Long> lifespan;

		public DBTraceAddressSnapRangePropertyMapNode(
				DBTraceAddressSnapRangePropertyMapTree<?, ?> tree, DBCachedObjectStore<?> store,
				DBRecord record) {
			super(store, record);
			this.tree = tree;
		}

		@Override
		protected void fresh(boolean created) throws IOException {
			super.fresh(created);
			if (created) {
				Address min = tree.mapSpace.getAddressSpace().getMinAddress();
				range = new AddressRangeImpl(min, min);
				lifespan = Range.closed(0L, 0L);
				return;
			}
			Address minAddr = tree.mapSpace.toAddress(minOffset);
			Address maxAddr = tree.mapSpace.toAddress(maxOffset);
			range = new AddressRangeImpl(minAddr, maxAddr);
			lifespan = DBTraceUtils.toRange(minSnap, maxSnap);
		}

		@Override
		protected NodeType getType() {
			return NodeType.values()[(typeAndChildCount >> NODE_TYPE_SHIFT) & NODE_TYPE_MASK];
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
		protected void setDataCount(int dataCount) {
			this.dataCount = dataCount;
			update(DATA_COUNT_COLUMN);
		}

		@Override
		public TraceAddressSnapRange getShape() {
			return this;
		}

		@Override
		public TraceAddressSnapRange getBounds() {
			return this;
		}

		@Override
		public void setShape(TraceAddressSnapRange shape) {
			minOffset = tree.mapSpace.assertInSpace(shape.getX1());
			maxOffset = tree.mapSpace.assertInSpace(shape.getX2());
			minSnap = shape.getY1();
			maxSnap = shape.getY2();
			update(MIN_ADDRESS_COLUMN, MAX_ADDRESS_COLUMN, MIN_SNAP_COLUMN, MAX_SNAP_COLUMN);

			range = shape.getRange();
			lifespan = shape.getLifespan();
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

		@Override
		protected int getDataCount() {
			return dataCount;
		}

		@Override
		public EuclideanSpace2D<Address, Long> getSpace() {
			return tree.space;
		}

		@Override
		public AddressRange getRange() {
			return range;
		}

		@Override
		public Range<Long> getLifespan() {
			return lifespan;
		}
	}

	public static abstract class AbstractDBTraceAddressSnapRangePropertyMapData<T>
			extends DBTreeDataRecord<TraceAddressSnapRange, TraceAddressSnapRange, T>
			implements TraceAddressSnapRange {
		static final String PARENT_COLUMN_NAME = "Parent";
		static final String MIN_ADDRESS_COLUMN_NAME = "MinAddress";
		static final String MAX_ADDRESS_COLUMN_NAME = "MaxAddress";
		static final String MIN_SNAP_COLUMN_NAME = "MinSnap";
		static final String MAX_SNAP_COLUMN_NAME = "MaxSnap";

		@DBAnnotatedColumn(PARENT_COLUMN_NAME)
		static DBObjectColumn PARENT_COLUMN;
		@DBAnnotatedColumn(MIN_ADDRESS_COLUMN_NAME)
		static DBObjectColumn MIN_ADDRESS_COLUMN;
		@DBAnnotatedColumn(MAX_ADDRESS_COLUMN_NAME)
		static DBObjectColumn MAX_ADDRESS_COLUMN;
		@DBAnnotatedColumn(MIN_SNAP_COLUMN_NAME)
		static DBObjectColumn MIN_SNAP_COLUMN;
		@DBAnnotatedColumn(MAX_SNAP_COLUMN_NAME)
		static DBObjectColumn MAX_SNAP_COLUMN;

		@DBAnnotatedField(column = PARENT_COLUMN_NAME, indexed = true)
		private long parentKey;
		@DBAnnotatedField(column = MIN_ADDRESS_COLUMN_NAME)
		private long minOffset;
		@DBAnnotatedField(column = MAX_ADDRESS_COLUMN_NAME)
		private long maxOffset;
		@DBAnnotatedField(column = MIN_SNAP_COLUMN_NAME)
		private long minSnap;
		@DBAnnotatedField(column = MAX_SNAP_COLUMN_NAME)
		private long maxSnap;

		protected final DBTraceAddressSnapRangePropertyMapTree<T, ? extends AbstractDBTraceAddressSnapRangePropertyMapData<T>> tree;

		protected AddressRange range;
		protected Range<Long> lifespan;

		public AbstractDBTraceAddressSnapRangePropertyMapData(
				DBTraceAddressSnapRangePropertyMapTree<T, ?> tree, DBCachedObjectStore<?> store,
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
			Address minAddr = tree.mapSpace.toAddress(minOffset);
			Address maxAddr = tree.mapSpace.toAddress(maxOffset);
			range = new AddressRangeImpl(minAddr, maxAddr);
			lifespan = DBTraceUtils.toRange(minSnap, maxSnap);
		}

		@Override
		public void setParentKey(long parentKey) {
			this.parentKey = parentKey;
			update(PARENT_COLUMN);
		}

		@Override
		public long getParentKey() {
			return parentKey;
		}

		@Override
		public void setShape(TraceAddressSnapRange shape) {
			minOffset = tree.mapSpace.assertInSpace(shape.getX1());
			maxOffset = shape.getX2().getOffset();
			minSnap = shape.getY1();
			maxSnap = shape.getY2();
			update(MIN_ADDRESS_COLUMN, MAX_ADDRESS_COLUMN, MIN_SNAP_COLUMN, MAX_SNAP_COLUMN);

			range = shape.getRange();
			lifespan = shape.getLifespan();
		}

		@Override
		public TraceAddressSnapRange getShape() {
			return this;
		}

		@Override
		public TraceAddressSnapRange getBounds() {
			return this;
		}

		@Override
		public EuclideanSpace2D<Address, Long> getSpace() {
			return tree.space;
		}

		@Override
		public AddressRange getRange() {
			return range;
		}

		@SuppressWarnings({ "unchecked", "hiding" })
		protected void doSetRange(AddressRange range) {
			@SuppressWarnings("rawtypes")
			DBTraceAddressSnapRangePropertyMapTree tree = this.tree;
			long newMinOffset = tree.mapSpace.assertInSpace(range.getMinAddress());
			tree.doUnparentEntry(this);
			minOffset = newMinOffset;
			maxOffset = range.getMaxAddress().getOffset();
			update(MIN_ADDRESS_COLUMN, MAX_ADDRESS_COLUMN);
			this.range = range;
			tree.doInsertDataEntry(this);
		}

		@SuppressWarnings({ "unchecked", "hiding" })
		protected void doSetLifespan(Range<Long> lifespan) {
			@SuppressWarnings("rawtypes")
			DBTraceAddressSnapRangePropertyMapTree tree = this.tree;
			tree.doUnparentEntry(this);
			minSnap = DBTraceUtils.lowerEndpoint(lifespan);
			maxSnap = DBTraceUtils.upperEndpoint(lifespan);
			update(MIN_SNAP_COLUMN, MAX_SNAP_COLUMN);
			this.lifespan = lifespan;
			tree.doInsertDataEntry(this);
		}

		@Override
		public Range<Long> getLifespan() {
			return lifespan;
		}

		@Override
		public boolean shapeEquals(TraceAddressSnapRange shape) {
			return doEquals(shape);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (!(obj instanceof AbstractDBTraceAddressSnapRangePropertyMapData<?>)) {
				/**
				 * TODO: I'm guessing Node v Data within the tree requires equals to perform shape
				 * comparison despite this and that having different types? If that's the case, we
				 * should probably test for node type explicitly.
				 */
				return doEquals(obj); // Permit just shape equality
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			@SuppressWarnings("unchecked")
			AbstractDBTraceAddressSnapRangePropertyMapData<T> that =
				(AbstractDBTraceAddressSnapRangePropertyMapData<T>) obj;
			if (this.tree == that.tree) {
				return this == that; // Require shape and value equality
			}
			if (!doEquals(obj)) {
				return false;
			}
			T thisVal = this.getRecordValue();
			T thatVal = that.getRecordValue();
			if (thisVal == this || thatVal == that) {
				return false;
			}
			if (!thisVal.equals(thatVal)) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			return doHashCode();
		}
	}

	public static class TraceAddressSnapRangeQuery extends
			AbstractRectangle2DQuery<Address, Long, TraceAddressSnapRange, TraceAddressSnapRange, TraceAddressSnapRangeQuery> {

		public static TraceAddressSnapRangeQuery at(Address address, long snap) {
			return intersecting(new ImmutableTraceAddressSnapRange(address, snap), null,
				TraceAddressSnapRangeQuery::new);
		}

		public TraceAddressSnapRangeQuery(TraceAddressSnapRange r1, TraceAddressSnapRange r2,
				Rectangle2DDirection direction) {
			super(r1, r2, r1.getSpace(), direction);
		}

		public AddressSpace getAddressSpace() {
			return r1.getRange().getAddressSpace();
		}

		@Override
		public boolean testData(TraceAddressSnapRange shape) {
			if (!r1.contains(shape.getX1(), shape.getY1())) {
				return false;
			}
			if (!r2.contains(shape.getX2(), shape.getY2())) {
				return false;
			}
			return true;
		}

		@Override
		protected TraceAddressSnapRangeQuery create(TraceAddressSnapRange ir1,
				TraceAddressSnapRange ir2, Rectangle2DDirection newDirection) {
			return new TraceAddressSnapRangeQuery(ir1, ir2, newDirection);
		}

		public static TraceAddressSnapRangeQuery enclosed(TraceAddressSnapRange range) {
			return enclosed(range, null, TraceAddressSnapRangeQuery::new);
		}

		public static TraceAddressSnapRangeQuery enclosed(AddressRange range,
				Range<Long> lifespan) {
			return enclosed(new ImmutableTraceAddressSnapRange(range, lifespan), null,
				TraceAddressSnapRangeQuery::new);
		}

		public static TraceAddressSnapRangeQuery enclosed(Address minAddress, Address maxAddress,
				long minSnap, long maxSnap) {
			return enclosed(
				new ImmutableTraceAddressSnapRange(minAddress, maxAddress, minSnap, maxSnap));
		}

		public static TraceAddressSnapRangeQuery intersecting(TraceAddressSnapRange range) {
			return intersecting(range, null, TraceAddressSnapRangeQuery::new);
		}

		public static TraceAddressSnapRangeQuery intersecting(AddressRange range,
				Range<Long> lifespan) {
			return intersecting(new ImmutableTraceAddressSnapRange(range, lifespan), null,
				TraceAddressSnapRangeQuery::new);
		}

		public static TraceAddressSnapRangeQuery intersecting(Address minAddress,
				Address maxAddress, long minSnap, long maxSnap) {
			return intersecting(
				new ImmutableTraceAddressSnapRange(minAddress, maxAddress, minSnap, maxSnap), null,
				TraceAddressSnapRangeQuery::new);
		}

		public static TraceAddressSnapRangeQuery atSnap(long snap, AddressSpace space) {
			return intersecting(new ImmutableTraceAddressSnapRange(space.getMinAddress(),
				space.getMaxAddress(), snap, snap), null, TraceAddressSnapRangeQuery::new);
		}

		public static TraceAddressSnapRangeQuery intersecting(Range<Long> lifespan,
				AddressSpace space) {
			return intersecting(new ImmutableTraceAddressSnapRange(space.getMinAddress(),
				space.getMaxAddress(), lifespan), null, TraceAddressSnapRangeQuery::new);
		}

		/**
		 * Find entries which do not exist at the from snap, but do exist at the to snap
		 * 
		 * <p>
		 * Note that entries created and then destroyed within the given span are not selected.
		 * 
		 * @param from the first snap to "compare"
		 * @param to the second snap to "compare"
		 * @param space the address space
		 * @return a query which can compare the two snaps, searching for entries added
		 */
		public static TraceAddressSnapRangeQuery added(long from, long to, AddressSpace space) {
			if (to < from) {
				return removed(to, from, space);
			}
			AddressRangeImpl rng =
				new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());
			return intersecting(rng, Range.closed(from + 1, to))
					.and(intersecting(rng, Range.atLeast(to)));
		}

		/**
		 * Find entries which exist at the from snap, but do not exist at the to snap
		 * 
		 * <p>
		 * Note that entries created and then destroyed within the given span are not selected.
		 * 
		 * @param from the first snap to "compare"
		 * @param to the second snap to "compare"
		 * @param space the address space
		 * @return a query which can compare the two snaps, searching for entries removed
		 */
		public static TraceAddressSnapRangeQuery removed(long from, long to, AddressSpace space) {
			if (to < from) {
				return added(to, from, space);
			}
			AddressRangeImpl rng =
				new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());
			return intersecting(rng, Range.closed(from, to - 1))
					.and(enclosed(rng, Range.atMost(from)));
		}

		public static TraceAddressSnapRangeQuery mostRecent(Address address, long snap) {
			return intersecting(
				new ImmutableTraceAddressSnapRange(address, address, Long.MIN_VALUE, snap),
				Rectangle2DDirection.TOPMOST, TraceAddressSnapRangeQuery::new);
		}

		public static TraceAddressSnapRangeQuery mostRecent(Address address, Range<Long> span) {
			return intersecting(
				new ImmutableTraceAddressSnapRange(address, span),
				Rectangle2DDirection.TOPMOST, TraceAddressSnapRangeQuery::new);
		}

		public static TraceAddressSnapRangeQuery equalTo(TraceAddressSnapRange shape) {
			return equalTo(shape, null, TraceAddressSnapRangeQuery::new);
		}

		public static TraceAddressSnapRangeQuery leftLower(Address address) {
			Address prev = address.previous();
			if (prev == null) {
				throw new NoSuchElementException();
			}
			return intersecting(address.getAddressSpace().getMinAddress(), prev, Long.MIN_VALUE,
				Long.MAX_VALUE);
		}

		public static TraceAddressSnapRangeQuery rightHigher(Address address) {
			Address next = address.next();
			if (next == null) {
				throw new NoSuchElementException();
			}
			return intersecting(next, address.getAddressSpace().getMaxAddress(), Long.MIN_VALUE,
				Long.MAX_VALUE);
		}
	}

	protected final DBTraceAddressSnapRangePropertyMapDataFactory<T, DR> dataFactory;
	protected final DBTraceAddressSnapRangePropertyMapSpace<T, DR> mapSpace;

	protected final DBCachedObjectIndex<Long, DBTraceAddressSnapRangePropertyMapNode> nodesByParent;
	protected final DBCachedObjectIndex<Long, DR> dataByParent;

	protected final Comparator<TraceAddressSnapRange> leftmostComparator;

	public DBTraceAddressSnapRangePropertyMapTree(DBCachedObjectStoreFactory storeFactory,
			String tableName, DBTraceAddressSnapRangePropertyMapSpace<T, DR> space,
			Class<DR> dataType, DBTraceAddressSnapRangePropertyMapDataFactory<T, DR> dataFactory,
			boolean upgradable) throws VersionException, IOException {
		super(storeFactory, tableName, TraceAddressSnapSpace.forAddressSpace(space.space), dataType,
			DBTraceAddressSnapRangePropertyMapNode.class, upgradable, MAX_CHILDREN);
		this.mapSpace = space;
		this.dataFactory = dataFactory;

		this.nodesByParent = nodeStore.getIndex(long.class,
			DBTraceAddressSnapRangePropertyMapNode.PARENT_COLUMN);
		this.dataByParent = dataStore.getIndex(long.class,
			AbstractDBTraceAddressSnapRangePropertyMapData.PARENT_COLUMN);

		this.leftmostComparator = Comparator.comparing(Rectangle2D::getX1, this.space::compareX);

		init();
	}

	@Override
	protected Comparator<TraceAddressSnapRange> getDefaultBoundsComparator() {
		return leftmostComparator;
	}

	@Override
	protected DR createDataEntry(DBCachedObjectStore<DR> store, DBRecord record) {
		return dataFactory.create(this, store, record);
	}

	@Override
	protected DBTraceAddressSnapRangePropertyMapNode createNodeEntry(
			DBCachedObjectStore<DBTraceAddressSnapRangePropertyMapNode> store, DBRecord record) {
		return new DBTraceAddressSnapRangePropertyMapNode(this, store, record);
	}

	protected Rectangle2DDirection getDirectionOf(TraceAddressSnapRangeQuery query) {
		if (query == null || query.getDirection() == null) {
			return Rectangle2DDirection.LEFTMOST;
		}
		return query.getDirection();
	}

	@Override
	protected Collection<DBTraceAddressSnapRangePropertyMapNode> getNodeChildrenOf(long parentKey) {
		return nodesByParent.get(parentKey);
	}

	@Override
	protected Collection<DR> getDataChildrenOf(long parentKey) {
		return dataByParent.get(parentKey);
	}

	@Override
	protected void doUnparentEntry(DR data) {
		super.doUnparentEntry(data);
	}

	@Override
	protected void doDeleteEntry(DR data) {
		super.doDeleteEntry(data);
	}

	protected void doInsertDataEntry(DR entry) {
		super.doInsert(entry, new LevelInfo(leafLevel));
	}

	public DBTraceAddressSnapRangePropertyMapSpace<T, DR> getMapSpace() {
		return mapSpace;
	}
}
