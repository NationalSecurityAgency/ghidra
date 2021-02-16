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

import java.io.IOException;
import java.util.*;

import com.google.common.collect.Collections2;

import ghidra.util.database.DBCachedObjectStoreFactory;
import ghidra.util.database.spatial.DBTreeNodeRecord.NodeType;
import ghidra.util.exception.VersionException;

/**
 * An R*-Tree implementation of {@link AbstractConstraintsTree}
 * 
 * <p>
 * The implementation follows
 * <a href="http://dbs.mathematik.uni-marburg.de/publications/myPapers/1990/BKSS90.pdf">The R*-tree:
 * An Efficient and Robust Access Method for Points and Rectangles</a>. Comments in code referring
 * to "the paper", specific sections, or steps of algorithms, are referring specifically to that
 * paper.
 * 
 * @param <DS> The shape of each data entry
 * @param <DR> The record type for each data entry
 * @param <NS> The shape of each node
 * @param <NR> The record type for each node
 * @param <T> The type of value stored in a data entry
 * @param <Q> The type of supported queries
 */
public abstract class AbstractRStarConstraintsTree< //
		DS extends BoundedShape<NS>, //
		DR extends DBTreeDataRecord<DS, NS, T>, //
		NS extends BoundingShape<NS>, //
		NR extends DBTreeNodeRecord<NS>, //
		T, //
		Q extends Query<DS, NS>> //
		extends AbstractConstraintsTree<DS, DR, NS, NR, T, Q> {

	protected static final int MAX_LEVELS = 64; // Outlandish! But BitSet uses at least one word

	protected static final double FILL_RATE = 0.4; // Taken from paper
	// NOTE: Deleting a node may cause it to have fewer than MIN_CHILDREN. I do not intend to
	// redistribute those.

	protected static final double REINSERT_RATE = 0.3; // Taken from paper

	protected static final int CHEAT_OVERLAP_COUNT = 32; // Take from paper. TODO Tune it

	protected class LeastAreaEnlargementThenLeastArea
			implements Comparable<LeastAreaEnlargementThenLeastArea> {
		private final NR node;
		private final double areaEnlargement;
		private final double area;

		public LeastAreaEnlargementThenLeastArea(NR node, NS bounds) {
			this.node = node;
			this.area = node.getShape().getArea();
			this.areaEnlargement = node.getShape().computeAreaUnionBounds(bounds) - area;
		}

		@Override
		public String toString() {
			return String.format("<least-enlargement: %s, node=%s>", areaEnlargement, node);
		}

		@Override
		public int compareTo(LeastAreaEnlargementThenLeastArea that) {
			int result;
			result = Double.compare(this.areaEnlargement, that.areaEnlargement);
			if (result != 0) {
				return result;
			}
			result = Double.compare(this.area, that.area);
			if (result != 0) {
				return result;
			}
			return 0;
		}
	}

	protected class LeastDistanceFromCenterToPoint
			implements Comparable<LeastDistanceFromCenterToPoint> {
		private final DBTreeRecord<?, ? extends NS> record;
		private final double distance;

		public LeastDistanceFromCenterToPoint(DBTreeRecord<?, ? extends NS> record,
				NS parentBounds) {
			this.record = record;
			this.distance = parentBounds.computeCentroidDistance(record.getBounds());
		}

		@Override
		public String toString() {
			return String.format("<least-distance: %s,record=%s>", distance, record);
		}

		@Override
		public int compareTo(LeastDistanceFromCenterToPoint that) {
			return Double.compare(this.distance, that.distance);
		}
	}

	protected final int maxChildren;
	protected final int minChildren;
	protected final int reinsertCount;

	public AbstractRStarConstraintsTree(DBCachedObjectStoreFactory storeFactory, String tableName,
			Class<DR> dataType, Class<NR> nodeType, boolean upgradable, int maxChildren)
			throws VersionException, IOException {
		super(storeFactory, tableName, dataType, nodeType, upgradable);

		this.maxChildren = maxChildren;
		minChildren = (int) (FILL_RATE * maxChildren);
		reinsertCount = (int) ((maxChildren + 1) * REINSERT_RATE);
	}

	protected abstract List<Comparator<NS>> getSplitAxes();

	/**
	 * The ChooseSubtree algorithm as defined in Section 4.1 of the paper.
	 * 
	 * @param dstLevel the level of the node to choose
	 * @param bounds the bounds of the object being inserted
	 * @return the leaf node into which the object should be inserted
	 */
	protected NR doChooseSubtree(int dstLevel, NS bounds) {
		// CS1
		NR node = root;

		// CS2
		for (int i = 0; i < dstLevel; i++) {
			assert !node.getType().isLeaf();
			if (node.getType().isLeafParent()) {
				node = findChildByNearlyMinimumOverlapCost(node, bounds);
			}
			else {
				assert node.getType().isDirectory();
				node = findChildByMinimumEnlargementCost(node, bounds);
			}
			// CS3 (by virtue of setting node, and the while loop
		}
		return node;
	}

	/**
	 * For ChooseSubTree, the part which chooses a leaf node using the minimum area enlargement
	 * cost.
	 * 
	 * @param n
	 * @param bounds
	 * @return
	 */
	protected NR findChildByMinimumEnlargementCost(NR n, NS bounds) {
		assert !n.getType().isLeafParent() && n.getType().isDirectory();
		NR bestChild = null;
		double bestAreaEnlargement = 0;
		for (NR child : getNodeChildrenOf(n)) {
			double candidateAreaEnlargement =
				child.getShape().computeAreaUnionBounds(bounds) - child.getShape().getArea();
			if (bestChild == null || candidateAreaEnlargement < bestAreaEnlargement ||
				(candidateAreaEnlargement == bestAreaEnlargement &&
					child.getShape().getArea() < bestChild.getShape().getArea())) {
				bestChild = child;
				bestAreaEnlargement = candidateAreaEnlargement;
			}
		}
		assert bestChild != null;
		return bestChild;
	}

	/**
	 * For ChooseSubtree, the part which chooses a leaf node using the <em>nearly</em> minimum
	 * overlap enlargement cost as defined in Section 4.1 of the paper, at the bottom of page 325.
	 * 
	 * <p>
	 * Ties are resolved using the minimum area enlargement cost.
	 * 
	 * @param n the node whose children are leaf nodes
	 * @param bounds the bounds of the object being inserted
	 * @return the leaf node into which the object should be inserted
	 */
	protected NR findChildByNearlyMinimumOverlapCost(NR n, NS bounds) {
		assert n.getType().isLeafParent();
		PriorityQueue<LeastAreaEnlargementThenLeastArea> sorted =
			new PriorityQueue<>(n.getChildCount());
		List<NR> children = new ArrayList<>(getNodeChildrenOf(n));
		for (NR leaf : children) {
			assert leaf.getType().isLeaf();
			sorted.offer(new LeastAreaEnlargementThenLeastArea(leaf, bounds));
		}
		NR bestLeaf = null;
		double bestOverlapEnlargement = 0;
		double bestAreaEnlargement = 0;
		for (int i = 0; i < CHEAT_OVERLAP_COUNT; i++) {
			LeastAreaEnlargementThenLeastArea measure = sorted.poll();
			if (measure == null) {
				break;
			}
			double candidateOverlap =
				computeOverlap(measure.node.getShape(), children, measure.node);
			double candidateOverlapEnlargement =
				computeOverlap(measure.node.getShape().unionBounds(bounds), children,
					measure.node) - candidateOverlap;
			if (bestLeaf == null || candidateOverlapEnlargement < bestOverlapEnlargement ||
				(candidateOverlapEnlargement == bestOverlapEnlargement &&
					measure.areaEnlargement < bestAreaEnlargement)) {
				bestLeaf = measure.node;
				bestOverlapEnlargement = candidateOverlapEnlargement;
				bestAreaEnlargement = measure.areaEnlargement;
			}
		}
		assert bestLeaf != null;
		return bestLeaf;
	}

	/**
	 * Computes the overlap of a bounding shape (with respect to its siblings)
	 * 
	 * <p>
	 * This measure is defined in Section 4.1 of the paper.
	 * 
	 * @param n the shape to measure
	 * @param all the sibling nodes (may contain {@code n}, which is ignored)
	 * @param ignore the node whose shape is being considered
	 * @return the overlap measure
	 */
	protected double computeOverlap(NS n, Iterable<NR> all, NR ignore) {
		double sum = 0;
		for (NR r : all) {
			if (r == ignore) {
				ignore = null;
				continue;
			}
			sum += n.computeAreaIntersection(r.getShape());
		}
		assert ignore == null;
		return sum;
	}

	protected static int sum(Iterable<Integer> terms) {
		int sum = 0;
		for (long t : terms) {
			sum += t;
		}
		return sum;
	}

	/**
	 * The Split algorithm as defined in Section 4.2 of the paper.
	 * 
	 * @param n the node to split
	 * @return the new node (containing the second group)
	 */
	protected NR doSplit(NR n) {
		List<DBTreeRecord<?, ? extends NS>> children = new ArrayList<>(getChildrenOf(n));
		assert children.size() == maxChildren + 1;

		// S1
		Comparator<NS> axis = doChooseSplitAxis(children);

		// S2
		int index = doChooseSplitIndex(children, axis);

		// S3
		// NOTE: Children are already sorted on the chosen axis
		List<DBTreeRecord<?, ? extends NS>> firstGroup = children.subList(0, index);
		List<DBTreeRecord<?, ? extends NS>> secondGroup = children.subList(index, children.size());

		// Keep the first group under the same node, but re-compute its bounds
		// Move the second group to a new node
		NR n1 = n;
		NR n2 = nodeStore.create();
		// NOTE: Careful here not to remove anything from node 0's entry
		n2.setParentKey(n.getParentKey());
		doAddToCachedChildren(n.getParentKey(), n2, cachedNodeChildren);
		n2.setType(n.getType());

		// Update existing node's metadata
		Collection<? extends NS> firstBounds =
			Collections2.transform(firstGroup, DBTreeRecord::getBounds);
		n1.setShape(BoundingShape.boundsUnion(firstBounds));
		n1.setChildCount(index);
		n1.setDataCount(sum(Collections2.transform(firstGroup, p -> p.getDataCount())));

		// Set new node's metadata
		Collection<? extends NS> secondBounds =
			Collections2.transform(secondGroup, DBTreeRecord::getBounds);
		n2.setShape(BoundingShape.boundsUnion(secondBounds));
		n2.setChildCount(maxChildren + 1 - index);
		n2.setDataCount(sum(Collections2.transform(secondGroup, p -> p.getDataCount())));

		// Move split-off children to new node
		if (n2.getType() == NodeType.LEAF) {
			for (DBTreeRecord<?, ?> move : secondGroup) {
				@SuppressWarnings("unchecked")
				DR dMove = (DR) move;
				doSetParentKey(dMove, n2.getKey(), cachedDataChildren);
			}
		}
		else {
			for (DBTreeRecord<?, ?> move : secondGroup) {
				@SuppressWarnings("unchecked")
				NR nMove = (NR) move;
				doSetParentKey(nMove, n2.getKey(), cachedNodeChildren);
			}
		}
		return n2;
	}

	protected Comparator<NS> doChooseSplitAxis(List<DBTreeRecord<?, ? extends NS>> children) {
		Comparator<NS> bestAxis = null;
		double bestMarginValue = Double.MAX_VALUE;
		// CSA1
		for (Comparator<NS> axis : getSplitAxes()) {
			children.sort(Comparator.comparing(DBTreeRecord::getBounds, axis));

			// Distributions as desribed in Section 4.2.
			// In the paper, S is defined as "the sum of all margin-values of the different distributions"
			// While the margin-value is defined as a sum. So just sum it all. No need to collect the groups,
			// or even pair their values.

			// Compute each area, incrementally, and sum them.
			// ************X (M = 12)
			// mmm-------mmm (m = 3)
			// 8 distributions : 12 - 2*3 + 2
			Collection<? extends NS> firstKBounds =
				Collections2.transform(children.subList(0, minChildren), DBTreeRecord::getBounds);
			NS boundsFirstKChildren = BoundingShape.boundsUnion(firstKBounds);
			Collection<? extends NS> lastKBounds = Collections2.transform(
				children.subList(maxChildren + 1 - minChildren, maxChildren + 1),
				DBTreeRecord::getBounds);
			NS bounsaLastKChildren = BoundingShape.boundsUnion(lastKBounds);
			int maxK = maxChildren + 1 - minChildren * 2;

			double marginValue = 0;
			marginValue += boundsFirstKChildren.getMargin();
			marginValue += bounsaLastKChildren.getMargin();
			for (int k = 0; k <= maxK; k++) { // NOTE: Our k is 0-up. Paper defines using 1-up.
				NS forFirst = children.get(minChildren + k).getBounds();
				NS forSecond = children.get(maxChildren - minChildren - k).getBounds();

				boundsFirstKChildren = boundsFirstKChildren.unionBounds(forFirst);
				bounsaLastKChildren = bounsaLastKChildren.unionBounds(forSecond);

				marginValue += boundsFirstKChildren.getMargin();
				marginValue += bounsaLastKChildren.getMargin();
			}

			// CSA2
			if (bestAxis == null || marginValue < bestMarginValue) {
				bestAxis = axis;
				bestMarginValue = marginValue;
			}
		}
		assert bestAxis != null;
		return bestAxis;
	}

	protected int doChooseSplitIndex(List<DBTreeRecord<?, ? extends NS>> children,
			Comparator<NS> axis) {
		children.sort(Comparator.comparing(DBTreeRecord::getBounds, axis));

		// Distributions as described in Section 4.2
		// Precompute the bounding boxes of each pair, incrementally.
		// ************X (M = 12)
		// mmm-------mmm (m = 3)
		// 8 distributions : 12 - 2*3 + 2

		Collection<? extends NS> firstBounds =
			Collections2.transform(children.subList(0, minChildren), DBTreeRecord::getBounds);
		NS boundsFirstKChildren = BoundingShape.boundsUnion(firstBounds);
		Collection<? extends NS> secondBounds =
			Collections2.transform(children.subList(maxChildren + 1 - minChildren, maxChildren + 1),
				DBTreeRecord::getBounds);
		NS boundsLastKChildren = BoundingShape.boundsUnion(secondBounds);
		int maxK = maxChildren + 1 - minChildren * 2;

		Deque<NS> boundsFirsts = new ArrayDeque<>();
		Deque<NS> boundsSeconds = new ArrayDeque<>();
		boundsFirsts.addLast(boundsFirstKChildren);
		boundsSeconds.addFirst(boundsLastKChildren);
		for (int k = 0; k <= maxK; k++) {
			NS forFirst = children.get(minChildren + k).getBounds();
			NS forSecond = children.get(maxChildren - minChildren - k).getBounds();

			boundsFirstKChildren = boundsFirstKChildren.unionBounds(forFirst);
			boundsLastKChildren = boundsLastKChildren.unionBounds(forSecond);

			boundsFirsts.addLast(boundsFirstKChildren);
			boundsSeconds.addFirst(boundsLastKChildren);
		}

		// CSI1
		double bestOverlapValue = Double.MAX_VALUE;
		double bestAreaValue = Double.MAX_VALUE;
		int bestIndex = -1;
		for (int k = 0; k <= maxK; k++) {
			NS boundsFirstGroup = boundsFirsts.removeFirst();
			NS boundsSecondGroup = boundsSeconds.removeFirst();
			double overlapValue = boundsFirstGroup.computeAreaIntersection(boundsSecondGroup);
			double areaValue = boundsFirstGroup.getArea() + boundsSecondGroup.getArea();
			if (bestIndex == -1 || overlapValue < bestOverlapValue ||
				(overlapValue == bestOverlapValue && areaValue < bestAreaValue)) {
				bestIndex = k;
				bestOverlapValue = overlapValue;
			}
		}
		assert bestIndex != -1;
		return bestIndex + minChildren;
	}

	protected static class LevelInfo {
		int dstLevel;
		long reinsertedLevels = 0; // MAX_LEVELS = 64

		public LevelInfo(int dstLevel) {
			this.dstLevel = dstLevel;
		}

		public boolean checkAndSetReinserted() {
			if ((reinsertedLevels >> dstLevel & 0x1) != 0) {
				return true;
			}
			reinsertedLevels |= (1 << dstLevel);
			return false;
		}

		public LevelInfo decLevel() {
			dstLevel--;
			return this;
		}

		public void incDepth() {
			dstLevel++;
			reinsertedLevels <<= 1;
		}
	}

	@Override
	protected DR doInsertData(DS shape, T value) {
		// ID1
		DR entry = dataStore.create();
		entry.setParentKey(-1); // TODO: Probably unnecessary, except error recovery?
		entry.setShape(shape);
		entry.setRecordValue(value);
		doInsert(entry, new LevelInfo(leafLevel));
		return entry;
	}

	// NOTE: entry may actually be a node
	protected void doInsert(DBTreeRecord<?, ? extends NS> entry, LevelInfo levelInfo) {
		// I1
		NR node = doChooseSubtree(levelInfo.dstLevel, entry.getBounds());

		// I2
		if (node.getType() == NodeType.LEAF) {
			@SuppressWarnings("unchecked")
			DR d = (DR) entry;
			doSetParentKey(d, node.getKey(), cachedDataChildren);
		}
		else {
			@SuppressWarnings("unchecked")
			NR n = (NR) entry;
			doSetParentKey(n, node.getKey(), cachedNodeChildren);
		}
		for (NR parent = node; parent != null; parent = getParentOf(parent)) {
			int newDataCount = parent.getDataCount() + entry.getDataCount();
			parent.setDataCount(newDataCount);
		}
		int newChildCount = node.getChildCount() + 1;
		node.setChildCount(newChildCount);

		// I4 - I'm having integrity issues unless this comes before overflow treatments		
		if (newChildCount == 1) {
			assert node == root;
			node.setShape(entry.getBounds());
		}
		else {
			for (NR parent = node; parent != null; parent = getParentOf(parent)) {
				parent.setShape(parent.getShape().unionBounds(entry.getBounds()));
			}
		}

		// I3
		NR split = null;
		if (newChildCount > maxChildren) {
			split = doOverflowTreatment(node, levelInfo);
		}
		// NOTE: Depth should never increase more than once per insert
		int savedLevel = levelInfo.dstLevel;
		for (NR propa = node, parent = getParentOf(propa); split != null; //
				propa = parent, //
				parent = getParentOf(propa), //
				split = doOverflowTreatment(propa, levelInfo.decLevel())) {
			if (parent == null) {
				assert propa == root;
				assert levelInfo.dstLevel == 0;
				root = nodeStore.create();
				root.setParentKey(-1);
				cachedNodeChildren.put(root.getKey(), new ArrayList<>(maxChildren));
				root.setShape(propa.getShape().unionBounds(split.getShape()));
				root.setType(propa.getType().getParentType());
				root.setChildCount(2);
				root.setDataCount(propa.getDataCount() + split.getDataCount());
				doSetParentKey(propa, root.getKey(), cachedNodeChildren);
				doSetParentKey(split, root.getKey(), cachedNodeChildren);
				leafLevel++;
				levelInfo.dstLevel = savedLevel;
				levelInfo.incDepth();
				return;
			}
			newChildCount = parent.getChildCount() + 1;
			parent.setChildCount(newChildCount);
			if (newChildCount <= maxChildren) {
				break;
			}
		}
		levelInfo.dstLevel = savedLevel;
	}

	protected NR doOverflowTreatment(NR n, LevelInfo levelInfo) {
		// OT1
		if (n != root && !levelInfo.checkAndSetReinserted()) {
			doReInsert(n, levelInfo);
			return null;
		}
		return doSplit(n);
	}

	protected void doReInsert(NR n, LevelInfo levelInfo) {
		// RI1, RI2
		// Create a "max heap"
		PriorityQueue<LeastDistanceFromCenterToPoint> farthest = new PriorityQueue<>();
		Iterator<? extends DBTreeRecord<?, ? extends NS>> it = getChildrenOf(n).iterator();
		for (int i = 0; i < reinsertCount; i++) {
			assert it.hasNext();
			DBTreeRecord<?, ? extends NS> next = it.next();
			farthest.add(new LeastDistanceFromCenterToPoint(next, n.getShape()));
		}
		/**
		 * Now that the heap is sized "reinsertCount", after each new entry, I can remove the
		 * nearest, knowing it can't possibly be selected for reinsertion. In the meantime, since I
		 * know each removed entry will remain in its parent, I can compute the new bounds of the
		 * parent.
		 */
		NS boundsNearest = null;
		int dataCountNearest = 0;
		while (it.hasNext()) {
			DBTreeRecord<?, ? extends NS> next = it.next();
			farthest.add(new LeastDistanceFromCenterToPoint(next, n.getShape()));
			LeastDistanceFromCenterToPoint near = farthest.poll();
			boundsNearest = boundsNearest == null ? near.record.getBounds()
					: boundsNearest.unionBounds(near.record.getBounds());
			dataCountNearest += near.record.getDataCount();
		}
		assert farthest.size() == reinsertCount;

		// RI3
		// NOTE: entries are removed as part of Insert step (by virtue of updated parent)
		n.setChildCount(maxChildren + 1 - reinsertCount);
		n.setShape(boundsNearest);
		int dataCountReduction = n.getDataCount() - dataCountNearest;
		n.setDataCount(dataCountNearest);
		NR p = getParentOf(n);
		while (p != null) {
			int newDataCount = p.getDataCount() - dataCountReduction;
			p.setDataCount(newDataCount);

			// I can't think of a better way to re-compute the bounds in the path
			Collection<? extends NS> childBounds =
				Collections2.transform(getChildrenOf(p), DBTreeRecord::getBounds);
			NS newBounds = BoundingShape.boundsUnion(childBounds);
			p.setShape(newBounds);

			p = getParentOf(p);
		}

		// RI4 (close reinsert)
		// NOTE: I know all children will be processed before we could possibly cause a split of n
		while (!farthest.isEmpty()) {
			LeastDistanceFromCenterToPoint far = farthest.poll();
			doInsert(far.record, levelInfo);
		}
	}

	@Override
	protected void checkNodeIntegrity(NR n) {
		super.checkNodeIntegrity(n);
		if (n.getChildCount() > maxChildren) {
			throw new AssertionError("Node exceeds the maximum children");
		}
	}
}
