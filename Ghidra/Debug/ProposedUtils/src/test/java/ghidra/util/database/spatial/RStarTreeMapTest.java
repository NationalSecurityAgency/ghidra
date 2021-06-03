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
package ghidra.util.database.spatial;

import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import javax.swing.JFrame;
import javax.swing.JPanel;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.*;

import com.google.common.collect.Iterators;

import db.DBHandle;
import db.DBRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.database.spatial.DBTreeNodeRecord.NodeType;
import ghidra.util.database.spatial.Query.QueryInclusion;
import ghidra.util.database.spatial.rect.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.ConsoleTaskMonitor;

public class RStarTreeMapTest {
	public enum Int2Space implements EuclideanSpace2D<Integer, Integer> {
		INSTANCE;

		@Override
		public int compareX(Integer x1, Integer x2) {
			return Integer.compare(x1, x2);
		}

		@Override
		public int compareY(Integer y1, Integer y2) {
			return Integer.compare(y1, y2);
		}

		@Override
		public double distX(Integer x1, Integer x2) {
			return Math.abs(x2 - x1);
		}

		@Override
		public double distY(Integer y1, Integer y2) {
			return Math.abs(y2 - y1);
		}

		@Override
		public Integer midX(Integer x1, Integer x2) {
			return x1 + (x2 - x1) / 2;
		}

		@Override
		public Integer midY(Integer y1, Integer y2) {
			return y1 + (y2 - y1) / 2;
		}

		@Override
		public IntRect getFull() {
			return IntRect.ALL;
		}
	}

	public static interface IntRect extends Rectangle2D<Integer, Integer, IntRect> {
		IntRect ALL = new ImmutableIntRect(Integer.MIN_VALUE, Integer.MAX_VALUE, Integer.MIN_VALUE,
			Integer.MAX_VALUE);

		@Override
		default IntRect immutable(Integer x1, Integer x2, Integer y1, Integer y2) {
			return new ImmutableIntRect(x1, x2, y1, y2);
		}
	}

	protected static class ImmutableIntRect extends ImmutableRectangle2D<Integer, Integer, IntRect>
			implements IntRect {
		public ImmutableIntRect(int x1, int x2, int y1, int y2) {
			super(x1, x2, y1, y2, Int2Space.INSTANCE);
		}

		@Override
		public IntRect getBounds() {
			return this;
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBIntRectStringDataRecord extends DBTreeDataRecord<IntRect, IntRect, String>
			implements IntRect {
		public static final String TABLE_NAME = "Strings";

		public static final String PARENT_COLUMN_NAME = "Parent";
		public static final String X1_COLUMN_NAME = "X1";
		public static final String X2_COLUMN_NAME = "Y1";
		public static final String Y1_COLUMN_NAME = "X2";
		public static final String Y2_COLUMN_NAME = "Y2";
		public static final String VAL_COLUMN_NAME = "Value";

		@DBAnnotatedColumn(PARENT_COLUMN_NAME)
		static DBObjectColumn PARENT_COLUMN;
		@DBAnnotatedColumn(X1_COLUMN_NAME)
		static DBObjectColumn X1_COLUMN;
		@DBAnnotatedColumn(X2_COLUMN_NAME)
		static DBObjectColumn X2_COLUMN;
		@DBAnnotatedColumn(Y1_COLUMN_NAME)
		static DBObjectColumn Y1_COLUMN;
		@DBAnnotatedColumn(Y2_COLUMN_NAME)
		static DBObjectColumn Y2_COLUMN;
		@DBAnnotatedColumn(VAL_COLUMN_NAME)
		static DBObjectColumn VAL_COLUMN;

		@DBAnnotatedField(column = PARENT_COLUMN_NAME, indexed = true)
		long parentKey;
		@DBAnnotatedField(column = X1_COLUMN_NAME)
		int x1;
		@DBAnnotatedField(column = X2_COLUMN_NAME)
		int x2;
		@DBAnnotatedField(column = Y1_COLUMN_NAME)
		int y1;
		@DBAnnotatedField(column = Y2_COLUMN_NAME)
		int y2;
		@DBAnnotatedField(column = VAL_COLUMN_NAME)
		String value;

		public DBIntRectStringDataRecord(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		@Override
		protected void setRecordValue(String value) {
			this.value = value;
			update(VAL_COLUMN);
		}

		@Override
		protected String getRecordValue() {
			return value;
		}

		@Override
		public String toString() {
			return String.format("<Data(%d): shape=%s,value=%s>", getKey(), description(), value);
		}

		@Override
		public String description() {
			return immutable(x1, x2, y1, y2).toString();
		}

		@Override
		protected boolean shapeEquals(IntRect shape) {
			return doEquals(shape);
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof DBIntRectStringDataRecord)) {
				return doEquals(obj);
			}
			return this == obj;
		}

		@Override
		public int hashCode() {
			return doHashCode();
		}

		@Override
		public Integer getX1() {
			return x1;
		}

		@Override
		public Integer getX2() {
			return x2;
		}

		@Override
		public Integer getY1() {
			return y1;
		}

		@Override
		public Integer getY2() {
			return y2;
		}

		@Override
		public EuclideanSpace2D<Integer, Integer> getSpace() {
			return Int2Space.INSTANCE;
		}

		@Override
		public IntRect getShape() {
			return this;
		}

		@Override
		public IntRect getBounds() {
			return this;
		}

		@Override
		public void setShape(IntRect shape) {
			this.x1 = shape.getX1();
			this.x2 = shape.getX2();
			this.y1 = shape.getY1();
			this.y2 = shape.getY2();
			update(X1_COLUMN, X2_COLUMN, Y1_COLUMN, Y2_COLUMN);
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

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBIntRectNodeRecord extends DBTreeNodeRecord<IntRect> implements IntRect {
		public static final String PARENT_COLUMN_NAME = "Parent";
		public static final String X1_COLUMN_NAME = "X1";
		public static final String X2_COLUMN_NAME = "Y1";
		public static final String Y1_COLUMN_NAME = "X2";
		public static final String Y2_COLUMN_NAME = "Y2";
		public static final String TYPE_COLUMN_NAME = "Type";
		public static final String CHILD_COUNT_COLUMN_NAME = "ChildCount";
		public static final String DATA_COUNT_COLUMN_NAME = "DataCount";

		@DBAnnotatedColumn(PARENT_COLUMN_NAME)
		static DBObjectColumn PARENT_COLUMN;
		@DBAnnotatedColumn(X1_COLUMN_NAME)
		static DBObjectColumn X1_COLUMN;
		@DBAnnotatedColumn(X2_COLUMN_NAME)
		static DBObjectColumn X2_COLUMN;
		@DBAnnotatedColumn(Y1_COLUMN_NAME)
		static DBObjectColumn Y1_COLUMN;
		@DBAnnotatedColumn(Y2_COLUMN_NAME)
		static DBObjectColumn Y2_COLUMN;
		@DBAnnotatedColumn(TYPE_COLUMN_NAME)
		static DBObjectColumn TYPE_COLUMN;
		@DBAnnotatedColumn(CHILD_COUNT_COLUMN_NAME)
		static DBObjectColumn CHILD_COUNT_COLUMN;
		@DBAnnotatedColumn(DATA_COUNT_COLUMN_NAME)
		static DBObjectColumn DATA_COUNT_COLUMN;

		@DBAnnotatedField(column = PARENT_COLUMN_NAME, indexed = true)
		long parentKey;
		@DBAnnotatedField(column = X1_COLUMN_NAME)
		int x1;
		@DBAnnotatedField(column = X2_COLUMN_NAME)
		int x2;
		@DBAnnotatedField(column = Y1_COLUMN_NAME)
		int y1;
		@DBAnnotatedField(column = Y2_COLUMN_NAME)
		int y2;
		@DBAnnotatedField(column = TYPE_COLUMN_NAME)
		NodeType type;
		@DBAnnotatedField(column = CHILD_COUNT_COLUMN_NAME)
		byte childCount;
		@DBAnnotatedField(column = DATA_COUNT_COLUMN_NAME)
		int dataCount;

		public DBIntRectNodeRecord(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		@Override
		public String toString() {
			return String.format("<Node(%s): shape=%s,type=%s,childCount=%s,dataCount=%s>",
				getKey(), description(), type, childCount, dataCount);
		}

		@Override
		public String description() {
			return immutable(x1, x2, y1, y2).toString();
		}

		@Override
		public boolean equals(Object obj) {
			return doEquals(obj);
		}

		@Override
		public int hashCode() {
			return doHashCode();
		}

		@Override
		public Integer getX1() {
			return x1;
		}

		@Override
		public Integer getX2() {
			return x2;
		}

		@Override
		public Integer getY1() {
			return y1;
		}

		@Override
		public Integer getY2() {
			return y2;
		}

		@Override
		public EuclideanSpace2D<Integer, Integer> getSpace() {
			return Int2Space.INSTANCE;
		}

		@Override
		protected NodeType getType() {
			return type;
		}

		@Override
		protected void setType(NodeType type) {
			this.type = type;
			update(TYPE_COLUMN);
		}

		@Override
		protected int getChildCount() {
			return childCount;
		}

		@Override
		protected void setChildCount(int childCount) {
			assert childCount < Byte.MAX_VALUE;
			this.childCount = (byte) childCount;
			update(CHILD_COUNT_COLUMN);
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
		public IntRect getShape() {
			return this;
		}

		@Override
		public IntRect getBounds() {
			return this;
		}

		@Override
		public void setShape(IntRect shape) {
			this.x1 = shape.getX1();
			this.x2 = shape.getX2();
			this.y1 = shape.getY1();
			this.y2 = shape.getY2();
			update(X1_COLUMN, X2_COLUMN, Y1_COLUMN, Y2_COLUMN);
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

	public static class IntRectQuery
			extends AbstractRectangle2DQuery<Integer, Integer, IntRect, IntRect, IntRectQuery> {

		public static IntRectQuery intersecting(IntRect rect) {
			return intersecting(rect, null, IntRectQuery::new);
		}

		public static IntRectQuery enclosing(IntRect rect) {
			return enclosing(rect, null, IntRectQuery::new);
		}

		public static IntRectQuery enclosed(IntRect rect) {
			return enclosed(rect, null, IntRectQuery::new);
		}

		public IntRectQuery(IntRect r1, IntRect r2, Rectangle2DDirection direction) {
			super(r1, r2, Int2Space.INSTANCE, direction);
		}

		@Override
		public String toString() {
			return String.format("<query 1:%s, 2:%s>", r1, r2);
		}

		@Override
		public boolean testData(IntRect shape) {
			if (!r1.contains(shape.getX1(), shape.getY1())) {
				return false;
			}
			if (!r2.contains(shape.getX2(), shape.getY2())) {
				return false;
			}
			return true;
		}

		@Override
		protected IntRectQuery create(IntRect ir1, IntRect ir2, Rectangle2DDirection newDirection) {
			return new IntRectQuery(ir1, ir2, newDirection);
		}
	}

	public static class IntRStarTree extends Abstract2DRStarTree< //
			Integer, Integer, // X,Y
			IntRect, DBIntRectStringDataRecord, // DS,DR
			IntRect, DBIntRectNodeRecord, // NS,NR
			String, IntRectQuery> { // T,Q

		protected final DBCachedObjectIndex<Long, DBIntRectNodeRecord> nodesByParent;
		protected final DBCachedObjectIndex<Long, DBIntRectStringDataRecord> dataByParent;

		protected final Comparator<IntRect> leftmostComparator;

		public IntRStarTree(DBCachedObjectStoreFactory storeFactory, String tableName,
				boolean upgradable, int maxChildren) throws VersionException, IOException {
			super(storeFactory, tableName, Int2Space.INSTANCE, DBIntRectStringDataRecord.class,
				DBIntRectNodeRecord.class, upgradable, maxChildren);

			this.nodesByParent = nodeStore.getIndex(long.class, DBIntRectNodeRecord.PARENT_COLUMN);
			this.dataByParent =
				dataStore.getIndex(long.class, DBIntRectStringDataRecord.PARENT_COLUMN);

			this.leftmostComparator =
				Comparator.comparing(Rectangle2D::getX1, this.space::compareX);

			init();
		}

		@Override
		protected Comparator<IntRect> getDefaultBoundsComparator() {
			return leftmostComparator;
		}

		@Override
		protected DBIntRectStringDataRecord createDataEntry(
				DBCachedObjectStore<DBIntRectStringDataRecord> store, DBRecord record) {
			return new DBIntRectStringDataRecord(store, record);
		}

		@Override
		protected DBIntRectNodeRecord createNodeEntry(
				DBCachedObjectStore<DBIntRectNodeRecord> store, DBRecord record) {
			return new DBIntRectNodeRecord(store, record);
		}

		@Override
		protected Collection<DBIntRectNodeRecord> getNodeChildrenOf(long parentKey) {
			return nodesByParent.get(parentKey);
		}

		@Override
		protected Collection<DBIntRectStringDataRecord> getDataChildrenOf(long parentKey) {
			return dataByParent.get(parentKey);
		}

		/*
		 * @Override protected DBIntRectNodeRecord doSplit(DBIntRectNodeRecord n) {
		 * System.out.println("Splitting " + n); System.out.println("  ParentBefore: " +
		 * getParentOf(n)); DBIntRectNodeRecord split = super.doSplit(n);
		 * System.out.println("  ParentAfter:  " + getParentOf(n)); System.out.println("  Node:  " +
		 * n); System.out.println("  Split: " + split); return split; }
		 * 
		 * @Override protected void doInsert(DBTreeRecord<?, ? extends IntRect> entry, int dstLevel,
		 * BitSet reinsertedLevels) { DBIntRectNodeRecord oldRoot = root;
		 * System.out.println("Inserting: " + entry + " into level " + dstLevel);
		 * super.doInsert(entry, dstLevel, reinsertedLevels); if (oldRoot != root) {
		 * System.out.println("  New root: " + root); } }
		 * 
		 * @Override protected DBIntRectNodeRecord doOverflowTreatment(DBIntRectNodeRecord n, int
		 * level, BitSet reinsertedLevels) { System.out.println( "Overflow on " + n + " at level " +
		 * level + ". Already " + reinsertedLevels); return super.doOverflowTreatment(n, level,
		 * reinsertedLevels); }
		 * 
		 * @Override protected void doReInsert(DBIntRectNodeRecord n, int level, BitSet
		 * reinsertedLevels) { System.out.println("Reinserting some children of " + n);
		 * super.doReInsert(n, level, reinsertedLevels); }
		 */

		protected void onScreen() {
			JFrame appWindow = new JFrame("View Tree");
			JPanel viewPanel = new JPanel() {
				Set<IntRect> selected = new HashSet<>();

				{
					addMouseListener(new MouseAdapter() {
						@Override
						public void mouseClicked(MouseEvent e) {
							int rootWidth = root.getX2() - root.getX1() + 1;
							int rootHeight = root.getY2() - root.getY1() + 1;
							int x = e.getX() * rootWidth / getWidth();
							int y = e.getY() * rootHeight / getHeight();
							selected.clear();
							selected.addAll(asSpatialMap().reduce(
								IntRectQuery.intersecting(rect(x, x, y, y))).keys());
							repaint();
						}
					});
				}

				void drawRect(Graphics g, IntRect rect, boolean fill) {
					int rootWidth = root.getX2() - root.getX1() + 1;
					int rootHeight = root.getY2() - root.getY1() + 1;
					int x1 = rect.getX1() * getWidth() / rootWidth;
					int x2 = rect.getX2() * getWidth() / rootWidth;
					int y1 = rect.getY1() * getHeight() / rootHeight;
					int y2 = rect.getY2() * getHeight() / rootHeight;
					if (fill) {
						g.fillRect(x1, y1, x2 - x1 + 1, y2 - y1 + 1);
					}
					else {
						g.drawRect(x1, y1, x2 - x1 + 1, y2 - y1 + 1);
					}
				}

				public void selectColor(Graphics g, NodeType type) {
					if (type.isLeaf()) {
						g.setColor(new Color(1, 0, 0, 0.5f).darker());
					}
					else if (type.isLeafParent()) {
						g.setColor(new Color(0, 1, 0, 0.5f).darker());
					}
					else {
						g.setColor(new Color(0, 0, 1, 0.5f).darker());
					}
				}

				public void drawPath(Graphics g, DBIntRectNodeRecord nr) {
					System.out.println("Onpath: " + nr);
					if (nr == root) {
						return;
					}
					drawPath(g, getParentOf(nr));
					g.setColor(Color.BLACK);
					drawRect(g, nr.getShape(), false);
				}

				public void drawPath(Graphics g, DBIntRectStringDataRecord dr) {
					System.out.println("Selected: " + dr);
					drawPath(g, getParentOf(dr));
					g.setColor(Color.BLACK);
					drawRect(g, dr.getBounds(), false);
				}

				@Override
				public void paint(Graphics g) {
					super.paint(g);
					visit(null, new TreeRecordVisitor() {
						@Override
						protected VisitResult beginNode(DBIntRectNodeRecord parent,
								DBIntRectNodeRecord n, QueryInclusion inclusion) {
							if (n != root) {
								selectColor(g, n.getType());
								drawRect(g, n.getBounds(), true);
							}
							return VisitResult.DESCEND;
						}

						@Override
						protected VisitResult visitData(DBIntRectNodeRecord parent,
								DBIntRectStringDataRecord d, boolean included) {
							g.setColor(new Color(0, 0, 0, 0.5f));
							drawRect(g, d.getShape(), true);
							return VisitResult.NEXT;
						}

					}, false);
					for (IntRect r : selected) {
						drawPath(g, (DBIntRectStringDataRecord) r);
					}
				}
			};
			appWindow.add(viewPanel);
			appWindow.setBounds(200, 200, 800, 600);
			appWindow.setVisible(true);
		}
	}

	public static class MyDomainObject extends DBCachedDomainObjectAdapter {
		private static final int MAX_CHILDREN = 5;
		private final DBCachedObjectStoreFactory storeFactory;
		private final IntRStarTree tree;
		private final SpatialMap<IntRect, String, IntRectQuery> map;

		protected MyDomainObject(Object consumer) throws IOException, VersionException {
			super(new DBHandle(), DBOpenMode.CREATE, new ConsoleTaskMonitor(), "Testing", 500, 1000,
				consumer);
			storeFactory = new DBCachedObjectStoreFactory(this);
			try (UndoableTransaction tid = UndoableTransaction.start(this, "CreateMaps", true)) {
				tree = new IntRStarTree(storeFactory, DBIntRectStringDataRecord.TABLE_NAME,
					true, MAX_CHILDREN);
				map = tree.asSpatialMap();
			}
		}

		protected MyDomainObject(File file, Object consumer) throws IOException, VersionException {
			super(new DBHandle(file), DBOpenMode.UPDATE, new ConsoleTaskMonitor(), "Testing", 500,
				1000, consumer);
			storeFactory = new DBCachedObjectStoreFactory(this);
			// No transaction, as tree should already exist
			tree = new IntRStarTree(storeFactory, DBIntRectStringDataRecord.TABLE_NAME,
				true, MAX_CHILDREN);
			map = tree.asSpatialMap();
		}

		@Override
		public boolean isChangeable() {
			return true;
		}

		@Override
		public String getDescription() {
			return "Testing";
		}
	}

	protected static IntRect rect(int x1, int x2, int y1, int y2) {
		return new ImmutableIntRect(x1, x2, y1, y2);
	}

	protected Iterator<IntRect> allRects(IntRect within) {
		return new Iterator<>() {
			int x1 = within.getX1();
			int x2 = within.getX1();
			int y1 = within.getY1();
			int y2 = within.getY1();

			@Override
			public boolean hasNext() {
				return x1 < within.getX2() || x2 < within.getX2() || y1 < within.getY2() ||
					y2 < within.getY2();
			}

			@Override
			public IntRect next() {
				if (y2 < within.getY2()) {
					y2++;
					return rect(x1, x2, y1, y2);
				}
				if (y1 < within.getY2()) {
					y2 = ++y1;
					return rect(x1, x2, y1, y2);
				}
				if (x2 < within.getX2()) {
					x2++;
					y2 = y1 = within.getY1();
					return rect(x1, x2, y1, y2);
				}
				if (x1 < within.getX2()) {
					x2 = ++x1;
					y2 = y1 = within.getY1();
					return rect(x1, x2, y1, y2);
				}
				throw new NoSuchElementException();
			}
		};
	}

	protected IntRect queryRect = rect(2, 3, 12, 13);
	protected IntRect range = rect(1, 4, 11, 14);

	protected MyDomainObject obj;

	@Before
	public void setUp() throws VersionException, IOException {
		obj = new MyDomainObject(this);
	}

	@After
	public void tearDown() {
		obj.release(this);
	}

	@Test
	public void testQueryIntersecting() {
		List<IntRect> expected = new ArrayList<>();
		Iterators.filter(allRects(range), queryRect::intersects).forEachRemaining(expected::add);

		IntRectQuery query = IntRectQuery.intersecting(queryRect);
		List<IntRect> actual = new ArrayList<>();
		Iterators.filter(allRects(range), query::testData).forEachRemaining(actual::add);

		assertEquals(expected, actual);
	}

	@Test
	public void testQueryEnclosing() {
		List<IntRect> expected = new ArrayList<>();
		Iterators.filter(allRects(range), queryRect::enclosedBy).forEachRemaining(expected::add);

		IntRectQuery query = IntRectQuery.enclosing(queryRect);
		List<IntRect> actual = new ArrayList<>();
		Iterators.filter(allRects(range), query::testData).forEachRemaining(actual::add);

		assertEquals(expected, actual);
	}

	@Test
	public void testQueryEnclosed() {
		List<IntRect> expected = new ArrayList<>();
		Iterators.filter(allRects(range), queryRect::encloses).forEachRemaining(expected::add);

		IntRectQuery query = IntRectQuery.enclosed(queryRect);
		List<IntRect> actual = new ArrayList<>();
		Iterators.filter(allRects(range), query::testData).forEachRemaining(actual::add);

		assertEquals(expected, actual);
	}

	@Test
	public void testQueryIntersectionAndIntersection() {
		IntRect queryRect1 = rect(1, 1, 12, 13);
		IntRect queryRect2 = rect(4, 4, 12, 13);
		List<IntRect> expected = new ArrayList<>();
		Iterators.filter(allRects(range),
			r -> queryRect1.intersects(r) && queryRect2.intersects(r))
				.forEachRemaining(
					expected::add);

		System.out.println(expected);

		IntRectQuery query =
			IntRectQuery.intersecting(queryRect1).and(IntRectQuery.intersecting(queryRect2));
		List<IntRect> actual = new ArrayList<>();
		Iterators.filter(allRects(range), query::testData).forEachRemaining(actual::add);

		assertEquals(expected, actual);
	}

	@Test
	public void testQueryIntersectingTestNode() {
		IntRectQuery query = IntRectQuery.intersecting(rect(2, 4, 12, 14));
		assertEquals(QueryInclusion.ALL, query.testNode(rect(3, 3, 13, 13)));
		assertEquals(QueryInclusion.ALL, query.testNode(rect(2, 4, 12, 14)));

		// There are many combinations, but the code is written one boundary at a time
		assertEquals(QueryInclusion.SOME, query.testNode(rect(3, 5, 13, 13))); // >
		assertEquals(QueryInclusion.SOME, query.testNode(rect(3, 3, 13, 15))); // ^
		assertEquals(QueryInclusion.SOME, query.testNode(rect(1, 3, 13, 13))); // <
		assertEquals(QueryInclusion.SOME, query.testNode(rect(3, 3, 11, 13))); // _

		// Again, many combos. Picking 4 simple.
		assertEquals(QueryInclusion.NONE, query.testNode(rect(5, 6, 12, 14))); // >>
		assertEquals(QueryInclusion.NONE, query.testNode(rect(2, 4, 15, 16))); // ^^
		assertEquals(QueryInclusion.NONE, query.testNode(rect(0, 1, 12, 14))); // <<
		assertEquals(QueryInclusion.NONE, query.testNode(rect(2, 4, 10, 11))); // __
	}

	@Test
	public void testQueryEnclosingTestNode() {
		IntRectQuery query = IntRectQuery.enclosing(rect(2, 4, 12, 14));
		assertEquals(QueryInclusion.NONE, query.testNode(rect(3, 3, 13, 13)));
		assertEquals(QueryInclusion.SOME, query.testNode(rect(2, 4, 12, 14)));

		// There are many combinations, but the code is written one boundary at a time
		assertEquals(QueryInclusion.NONE, query.testNode(rect(3, 5, 13, 13))); // >
		assertEquals(QueryInclusion.NONE, query.testNode(rect(3, 3, 13, 15))); // ^
		assertEquals(QueryInclusion.NONE, query.testNode(rect(1, 3, 13, 13))); // <
		assertEquals(QueryInclusion.NONE, query.testNode(rect(3, 3, 11, 13))); // _

		// Again, many combos. Picking 4 simple.
		assertEquals(QueryInclusion.NONE, query.testNode(rect(5, 6, 12, 14))); // >>
		assertEquals(QueryInclusion.NONE, query.testNode(rect(2, 4, 15, 16))); // ^^
		assertEquals(QueryInclusion.NONE, query.testNode(rect(0, 1, 12, 14))); // <<
		assertEquals(QueryInclusion.NONE, query.testNode(rect(2, 4, 10, 11))); // __
	}

	@Test
	public void testQueryEnclosedTestNode() {
		IntRectQuery query = IntRectQuery.enclosed(rect(2, 4, 12, 14));
		assertEquals(QueryInclusion.ALL, query.testNode(rect(3, 3, 13, 13)));
		assertEquals(QueryInclusion.ALL, query.testNode(rect(2, 4, 12, 14)));

		// There are many combinations, but the code is written one boundary at a time
		assertEquals(QueryInclusion.SOME, query.testNode(rect(3, 5, 13, 13))); // >
		assertEquals(QueryInclusion.SOME, query.testNode(rect(3, 3, 13, 15))); // ^
		assertEquals(QueryInclusion.SOME, query.testNode(rect(1, 3, 13, 13))); // <
		assertEquals(QueryInclusion.SOME, query.testNode(rect(3, 3, 11, 13))); // _

		// Again, many combos. Picking 4 simple.
		assertEquals(QueryInclusion.NONE, query.testNode(rect(5, 6, 12, 14))); // >>
		assertEquals(QueryInclusion.NONE, query.testNode(rect(2, 4, 15, 16))); // ^^
		assertEquals(QueryInclusion.NONE, query.testNode(rect(0, 1, 12, 14))); // <<
		assertEquals(QueryInclusion.NONE, query.testNode(rect(2, 4, 10, 11))); // __
	}

	protected static List<Pair<IntRect, String>> generateRandom(IntRect range, int maxW, int maxH,
			int count) {
		Random r = new Random();
		List<Pair<IntRect, String>> result = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			int w = r.nextInt(maxW); // Actually one less
			int h = r.nextInt(maxH); // Actually one less
			int dx = r.nextInt(range.getX2() - range.getX1() - w);
			int dy = r.nextInt(range.getY2() - range.getY1() - h);
			int x1 = range.getX1() + dx;
			int y1 = range.getY1() + dy;
			int x2 = x1 + w;
			int y2 = y1 + h;
			result.add(new ImmutablePair<>(rect(x1, x2, y1, y2), "V" + i));
		}
		return result;
	}

	@Test
	public void testIntegrityWith125RandomRects100x100Max10x10() throws Exception {
		// NOTE: This "thrashing" test covers nearly all the R*-Tree insertion logic.
		List<Pair<IntRect, String>> entries = generateRandom(rect(0, 100, 0, 100), 10, 10, 125);
		obj.tree.checkIntegrity();

		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddRandom", true)) {
			for (Entry<IntRect, String> ent : entries) {
				obj.map.put(ent.getKey(), ent.getValue());
				obj.tree.checkIntegrity();
			}
		}

		//obj.tree.onScreen();
		//Thread.sleep(Long.MAX_VALUE); // Meh
	}

	@Test
	public void testIntegrityWith1000RandomRects100x100Max10x10Using2Threads() throws Exception {
		// NOTE: This "thrashing" test covers nearly all the R*-Tree insertion logic.
		List<Pair<IntRect, String>> entries = generateRandom(rect(0, 100, 0, 100), 10, 10, 1000);
		Consumer<List<Pair<IntRect, String>>> inserter = list -> {
			try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddRandom", true)) {
				int i = 0;
				for (Entry<IntRect, String> ent : list) {
					System.err.println("Adding (sub) " + i++);
					obj.map.put(ent.getKey(), ent.getValue());
					// Note, underlying tree is not synchronized, but map is
					try (LockHold hold = LockHold.lock(obj.getReadWriteLock().readLock())) {
						obj.tree.checkIntegrity();
					}
				}
			}
		};

		obj.tree.checkIntegrity();
		int cut = entries.size() / 2;
		CompletableFuture<Void> thread1 =
			CompletableFuture.runAsync(() -> inserter.accept(entries.subList(0, cut)));
		CompletableFuture<Void> thread2 =
			CompletableFuture.runAsync(() -> inserter.accept(entries.subList(cut, entries.size())));
		thread1.get();
		thread2.get();

		obj.tree.checkIntegrity();

		//obj.tree.onScreen();
		//Thread.sleep(Long.MAX_VALUE); // Meh
	}

	@Test
	public void testIntegrityWith2000VerticallyStackedRects() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddVertical", true)) {
			for (int i = 0; i < 2000; i++) {
				System.err.println("Adding " + i);
				obj.map.put(rect(0, 10, i, i + 1), "Ent" + i);
				// Note, underlying tree is not synchronized, but map is
				/*try (LockHold hold = LockHold.lock(obj.getReadWriteLock().readLock())) {
					obj.tree.checkIntegrity();
				}*/
			}
		}
	}

	@Test
	public void testSaveAndLoad() throws IOException, CancelledException, VersionException {
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddRecord", true)) {
			obj.map.put(rect(1, 5, 6, 10), "Some value");
		}

		Path tmp = Files.createTempFile("test", ".db");
		Files.delete(tmp); // saveAs must create the file
		obj.getDBHandle().saveAs(tmp.toFile(), false, new ConsoleTaskMonitor());
		MyDomainObject loaded = null;

		try {
			loaded = new MyDomainObject(tmp.toFile(), this);

			assert loaded.map.entries()
					.contains(
						new ImmutablePair<>(rect(1, 5, 6, 10), "Some value"));
		}
		finally {
			if (loaded != null) {
				loaded.release(this);
			}
		}
	}

	protected List<Pair<IntRect, String>> generatePoints(IntRect within) {
		List<Pair<IntRect, String>> result = new ArrayList<>();
		for (int x1 = within.getX1(); x1 <= within.getX2(); x1++) {
			for (int y1 = within.getY1(); y1 <= within.getY2(); y1++) {
				result.add(
					new ImmutablePair<>(rect(x1, x1, y1, y1), "Point(" + x1 + "," + y1 + ")"));
			}
		}
		return result;
	}

	/**
	 * @throws InterruptedException maybe when Thread.sleep is uncommented
	 */
	@Test
	public void testCount() throws InterruptedException {
		// NOTE: This test is made also to cover the visitation logic.
		assertTrue(obj.map.isEmpty());

		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddPoints", true)) {
			for (Entry<IntRect, String> ent : generatePoints(rect(1, 12, 1, 12))) {
				obj.map.put(ent.getKey(), ent.getValue());
			}
		}

		//obj.tree.onScreen();
		//Thread.sleep(Long.MAX_VALUE);

		assertEquals(72, obj.map.reduce(IntRectQuery.enclosed(rect(1, 6, 1, 12))).size());
		assertFalse(obj.map.reduce(IntRectQuery.enclosed(rect(1, 6, 1, 12))).isEmpty());
		assertEquals(1, obj.map.reduce(IntRectQuery.enclosed(rect(6, 6, 6, 6))).size());
		assertFalse(obj.map.reduce(IntRectQuery.enclosed(rect(6, 6, 6, 6))).isEmpty());
		assertEquals(0, obj.map.reduce(IntRectQuery.enclosed(rect(20, 100, 20, 100))).size());
		assertTrue(obj.map.reduce(IntRectQuery.enclosed(rect(20, 100, 20, 100))).isEmpty());
	}

	@Test
	public void testFirst() {
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddPoints", true)) {
			for (Entry<IntRect, String> ent : generatePoints(rect(1, 12, 1, 12))) {
				obj.map.put(ent.getKey(), ent.getValue());
			}
		}

		//obj.tree.dump(null);

		assertEquals("Point(1,6)",
			obj.map.reduce(IntRectQuery.enclosed(rect(1, 12, 6, 6))).firstValue());
		assertEquals("Point(2,6)",
			obj.map.reduce(IntRectQuery.enclosed(rect(2, 12, 6, 6))).firstValue());
		assertEquals("Point(3,6)",
			obj.map.reduce(IntRectQuery.enclosed(rect(3, 12, 6, 6))).firstValue());
		assertEquals("Point(8,6)",
			obj.map.reduce(IntRectQuery.enclosed(rect(8, 12, 6, 6))).firstValue());
		assertEquals("Point(12,6)",
			obj.map.reduce(IntRectQuery.enclosed(rect(12, 12, 6, 6))).firstValue());

		assertEquals("Point(12,6)",
			obj.map.reduce(IntRectQuery.enclosed(rect(1, 12, 6, 6))
					.starting(
						Rectangle2DDirection.RIGHTMOST))
					.firstValue());
		assertEquals("Point(6,1)", obj.map.reduce(IntRectQuery.enclosed(rect(6, 6, 1, 12))
				.starting(
					Rectangle2DDirection.BOTTOMMOST))
				.firstValue());
		assertEquals("Point(6,12)",
			obj.map.reduce(IntRectQuery.enclosed(rect(6, 6, 1, 12))
					.starting(
						Rectangle2DDirection.TOPMOST))
					.firstValue());
	}

	@Test
	public void testIterator() {
		List<Pair<IntRect, String>> points = generatePoints(rect(1, 12, 1, 12));
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddPoints", true)) {
			for (Entry<IntRect, String> ent : points) {
				obj.map.put(ent.getKey(), ent.getValue());
			}
		}

		Map<IntRect, String> expected = new HashMap<>();
		Map<IntRect, String> actual = new HashMap<>();
		points.iterator().forEachRemaining(e -> expected.put(e.getKey(), e.getValue()));
		obj.map.entries().iterator().forEachRemaining(e -> actual.put(e.getKey(), e.getValue()));
		assertEquals(expected, actual);

		expected.clear();
		actual.clear();
		points.stream()
				.filter(e -> e.getKey().enclosedBy(rect(1, 6, 1, 12)))
				.forEach(
					e -> expected.put(e.getKey(), e.getValue()));
		assertEquals(72, expected.size()); // Sanity check on expected
		obj.map.reduce(IntRectQuery.enclosed(rect(1, 6, 1, 12)))
				.entries()
				.stream()
				.forEach(
					e -> actual.put(e.getKey(), e.getValue()));
		assertEquals(expected, actual);
	}

	@Test
	public void testOrderedIterator() {
		List<Pair<IntRect, String>> points = generatePoints(rect(1, 12, 1, 12));
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddPoints", true)) {
			for (Entry<IntRect, String> ent : points) {
				obj.map.put(ent.getKey(), ent.getValue());
			}
		}
		obj.tree.checkIntegrity();

		List<String> expected;
		List<String> actual;

		expected = List.of("Point(1,6)", "Point(2,6)", "Point(3,6)", "Point(4,6)", "Point(5,6)",
			"Point(6,6)");
		actual = new ArrayList<>(
			obj.map.reduce(IntRectQuery.enclosed(rect(1, 6, 6, 6))).orderedValues());
		assertEquals(expected, actual);

		expected = List.of("Point(6,6)", "Point(5,6)", "Point(4,6)", "Point(3,6)", "Point(2,6)",
			"Point(1,6)");
		actual = new ArrayList<>(obj.map.reduce(IntRectQuery.enclosed(rect(1, 6, 6, 6))
				.starting(
					Rectangle2DDirection.RIGHTMOST))
				.orderedValues());
	}

	@Test
	public void testRemove() {
		// TODO: Add a "minimal query including" abstract method to reduce search for removed item
		List<Pair<IntRect, String>> points = generatePoints(rect(1, 12, 1, 12));
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddPoints", true)) {
			for (Entry<IntRect, String> ent : points) {
				obj.map.put(ent.getKey(), ent.getValue());
			}
		}

		try (UndoableTransaction tid = UndoableTransaction.start(obj, "RemovePoints", true)) {
			assertFalse(obj.map.reduce(IntRectQuery.enclosed(rect(6, 6, 6, 6))).isEmpty());
			obj.map.remove(rect(6, 6, 6, 6), "NotHere");
			assertFalse(obj.map.reduce(IntRectQuery.enclosed(rect(6, 6, 6, 6))).isEmpty());
			obj.map.remove(rect(6, 6, 6, 6), "Point(6,6)");
			obj.tree.checkIntegrity();
			assertTrue(obj.map.reduce(IntRectQuery.enclosed(rect(6, 6, 6, 6))).isEmpty());

			for (Entry<IntRect, String> ent : obj.map.entries()) {
				obj.map.remove(ent.getKey(), ent.getValue());
				obj.tree.checkIntegrity();
			}
		}

		assertTrue(obj.map.isEmpty());
	}

	@Test
	public void testClear() {
		List<Pair<IntRect, String>> points = generatePoints(rect(1, 12, 1, 12));
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddPoints", true)) {
			for (Entry<IntRect, String> ent : points) {
				obj.map.put(ent.getKey(), ent.getValue());
			}
		}

		try (UndoableTransaction tid = UndoableTransaction.start(obj, "RemovePoints", true)) {
			obj.map.reduce(IntRectQuery.enclosed(rect(6, 6, 6, 6))).clear();
			obj.tree.checkIntegrity();
			assertEquals(143, obj.map.size());
			assertFalse(obj.map.values().contains("Point(6,6)"));

			obj.map.reduce(IntRectQuery.enclosed(rect(1, 6, 1, 12))).clear();
			obj.tree.checkIntegrity();
			assertEquals(72, obj.map.size());
			Map<IntRect, String> expected = new HashMap<>();
			Map<IntRect, String> actual = new HashMap<>();
			points.stream()
					.filter(e -> e.getKey().enclosedBy(rect(7, 12, 1, 12)))
					.forEach(
						e -> expected.put(e.getKey(), e.getValue()));
			obj.map.entries().stream().forEach(e -> actual.put(e.getKey(), e.getValue()));
			assertEquals(expected, actual);

			obj.map.clear();
			obj.tree.checkIntegrity();
			assertTrue(obj.map.isEmpty());
		}
	}

	// TODO: Entries, keys to array
	// TODO: Variant given an array of specified component type

	@Test
	public void testValuesToArray() {
		List<Pair<IntRect, String>> points = generatePoints(rect(1, 12, 1, 12));
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "AddPoints", true)) {
			for (Entry<IntRect, String> ent : points) {
				obj.map.put(ent.getKey(), ent.getValue());
			}
		}

		List<String> expected = List.of("Point(6,6)");
		List<String> actual =
			new ArrayList<>(obj.map.reduce(IntRectQuery.enclosed(rect(6, 6, 6, 6))).values());
		assertEquals(expected, actual);
	}
}
