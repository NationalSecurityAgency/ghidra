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
import java.util.Map.Entry;
import java.util.function.Consumer;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalNotification;
import com.google.common.collect.Collections2;

import db.DBRecord;
import generic.NestedIterator;
import generic.util.PeekableIterator;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.spatial.DBTreeNodeRecord.NodeType;
import ghidra.util.database.spatial.Query.QueryInclusion;
import ghidra.util.exception.VersionException;

public abstract class AbstractConstraintsTree< //
		DS extends BoundedShape<NS>, //
		DR extends DBTreeDataRecord<DS, NS, T>, //
		NS extends BoundingShape<NS>, //
		NR extends DBTreeNodeRecord<NS>, //
		T, //
		Q extends Query<DS, NS>> {

	protected final DBCachedObjectStore<DR> dataStore;
	protected final DBCachedObjectStore<NR> nodeStore;

	protected final Map<Long, Collection<DR>> cachedDataChildren = CacheBuilder.newBuilder()
			.removalListener(this::cachedDataChildrenRemoved)
			.concurrencyLevel(4)
			.maximumSize(50)
			.build()
			.asMap();
	protected final Map<Long, Collection<NR>> cachedNodeChildren = CacheBuilder.newBuilder()
			.removalListener(this::cachedNodeChildrenRemoved)
			.concurrencyLevel(4)
			.maximumSize(50)
			.build()
			.asMap();

	protected NR root;
	protected int leafLevel;

	public AbstractConstraintsTree(DBCachedObjectStoreFactory storeFactory, String tableName,
			Class<DR> dataType, Class<NR> nodeType, boolean upgradable)
			throws VersionException, IOException {
		this.dataStore = storeFactory.getOrCreateCachedStore(tableName, dataType,
			this::createDataEntry, upgradable);
		this.nodeStore = storeFactory.getOrCreateCachedStore(tableName + "_Nodes", nodeType,
			this::createNodeEntry, upgradable);
	}

	private void cachedDataChildrenRemoved(RemovalNotification<Long, Collection<DR>> rn) {
		// Nothing
	}

	private void cachedNodeChildrenRemoved(RemovalNotification<Long, Collection<NR>> rn) {
		// Nothing
	}

	protected abstract DR createDataEntry(DBCachedObjectStore<DR> store, DBRecord record);

	protected abstract NR createNodeEntry(DBCachedObjectStore<NR> store, DBRecord record);

	protected void init() {
		assert root == null;
		root = getOrCreateRoot();
		leafLevel = computeLeafLevel();
	}

	protected abstract Comparator<NS> getDefaultBoundsComparator();

	/**
	 * For non-leaf nodes, get the children.
	 * 
	 * For leaf nodes, the behavior is undefined. Note that the query should not filter the
	 * children, only order them. Filtering is performed by {@link TreeRecordVisitor}.
	 * 
	 * @param parentKey the key of the parent whose children to get
	 * @return an iterable of the children
	 */
	protected abstract Collection<NR> getNodeChildrenOf(long parentKey);

	/**
	 * For non-leaf nodes, get the children.
	 * 
	 * For leaf nodes, the behavior is undefined. Note that the query should not filter the
	 * children, only order them, or else the collection will return an incorrect
	 * {@link Collection#size()}. Filtering is performed by {@link TreeRecordVisitor}.
	 * 
	 * @param parent the parent node
	 * @return a collection of the children
	 */
	protected Collection<NR> getNodeChildrenOf(NR parent) {
		return cachedNodeChildren.computeIfAbsent(parent.getKey(),
			k -> new ArrayList<>(getNodeChildrenOf(k)));
	}

	/**
	 * For leaf nodes, get the children.
	 * 
	 * For non-leaf nodes, the behavior is undefined. Note that the query should not filter the
	 * children, only order them, or else the collection will return an incorrect
	 * {@link Collection#size()}. Filtering is performed by {@link TreeRecordVisitor}.
	 * 
	 * @param parentKey the key of the parent whose children to get
	 * @return an iterable of the children
	 */
	protected abstract Collection<DR> getDataChildrenOf(long parentKey);

	/**
	 * For leaf nodes, get the children.
	 * 
	 * For non-leaf nodes, the behavior is undefined. Note that the query should not filter the
	 * children, only order them, or else the collection will return an incorrect
	 * {@link Collection#size()}. Filtering is performed by {@link TreeRecordVisitor}.
	 * 
	 * @param parent the parent node
	 * @param query a query to control the ordering of the children
	 * @return a collection of the children
	 */
	protected Collection<DR> getDataChildrenOf(NR parent) {
		return cachedDataChildren.computeIfAbsent(parent.getKey(),
			k -> new ArrayList<>(getDataChildrenOf(k)));
	}

	/**
	 * Get the children.
	 * 
	 * Because the children may be either nodes or data, the exact type is not known. The only
	 * guarantee is that it is a tree record, which permits access to its bounds and parent. Note
	 * that the query should not filter the children, only order them, or else the collection will
	 * return an incorrect {@link Collection#size()}. Filtering is performed by
	 * {@link TreeRecordVisitor}.
	 * 
	 * @param parent the parent node
	 * @param query a query to control the ordering of the children
	 * @return a collection of the children
	 */
	protected Collection<? extends DBTreeRecord<?, ? extends NS>> getChildrenOf(NR parent) {
		if (parent.getType().isLeaf()) {
			return getDataChildrenOf(parent);
		}
		return getNodeChildrenOf(parent);
	}

	protected NR getParentOf(DBTreeRecord<?, ?> n) {
		return nodeStore.getObjectAt(n.getParentKey());
	}

	protected NR getOrCreateRoot() {
		Iterator<NR> oneRoot = getNodeChildrenOf(-1).iterator();
		if (oneRoot.hasNext()) {
			return oneRoot.next();
		}
		assert nodeStore.getRecordCount() == 0;
		NR r = nodeStore.create();
		r.setParentKey(-1);
		r.setType(NodeType.LEAF);
		cachedDataChildren.put(r.getKey(), new ArrayList<>());
		return r;
	}

	// NOTE: Only call this at instantiation. After that, it's easy to keep up-to-date.
	protected int computeLeafLevel() {
		for (DR data : dataStore.asMap().values()) {
			NR parent = getParentOf(data);
			if (parent == null) {
				continue; // Orphan
			}
			int level = 0;
			while (parent != root) {
				level++;
				parent = getParentOf(parent);
			}
			return level;
		}
		return 0;
	}

	protected abstract DR doInsertData(DS shape, T value);

	protected enum VisitResult {
		TERMINATE, NEXT, DESCEND, ASCEND;
	}

	protected abstract class TreeRecordVisitor {
		protected abstract VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion);

		/**
		 * Called when a node is finished being visited.
		 * 
		 * This only applies to nodes into which the visitor descends. The visitor will finish a
		 * node in one of three ways: 1) The node's children have all been visited. 2) The visitor
		 * returned {@link VisitResult#TERMINATE} while visiting a descendant. 3) The visitor
		 * returned {@link VisitResult#ASCEND} while visiting a child.
		 * 
		 * This method may return any result except {@link VisitResult#DESCEND}. If the visitor is
		 * terminating, the return value of this method is ignored.
		 * 
		 * @param parent the parent of this node, or {@code null} when visiting the root
		 * @param n the node currently being visited
		 * @param inclusion the original inclusion of the query before descending
		 * @return a directive for how the visitor should proceed
		 */
		protected VisitResult endNode(NR parent, NR n, QueryInclusion inclusion) {
			return VisitResult.NEXT;
		}

		protected abstract VisitResult visitData(NR parent, DR d, boolean included);
	}

	protected VisitResult visit(Q query, TreeRecordVisitor visitor, boolean ordered) {
		return visit(null, root, query, visitor, ordered);
	}

	protected VisitResult visit(NR parent, NR node, Q query, TreeRecordVisitor visitor,
			boolean ordered) {
		QueryInclusion inclusion =
			query == null ? QueryInclusion.ALL : query.testNode(node.getShape());
		VisitResult r = visitor.beginNode(parent, node, inclusion);
		if (r != VisitResult.DESCEND) {
			return r;
		}
		if (node.getType().isLeaf()) {
			List<DR> data = new ArrayList<>(getDataChildrenOf(node));
			if (query != null && ordered) {
				data.sort(Comparator.comparing(DR::getBounds, query.getBoundsComparator()));
			}
			for (DR d : data) {
				if (query != null && ordered && query.terminateEarlyData(d.getShape())) {
					break;
				}
				boolean included = query == null || query.testData(d.getShape());
				r = visitor.visitData(node, d, included);
				if (r == VisitResult.ASCEND) {
					return visitor.endNode(parent, node, inclusion);
				}
				if (r == VisitResult.TERMINATE) {
					visitor.endNode(parent, node, inclusion);
					return r;
				}
			}
			return visitor.endNode(parent, node, inclusion);
		}
		assert node.getType().isDirectory();
		List<NR> nodes = new ArrayList<>(getNodeChildrenOf(node));
		if (query != null && ordered) {
			nodes.sort(Comparator.comparing(NR::getBounds, query.getBoundsComparator()));
		}
		for (NR n : nodes) {
			if (query != null && ordered && query.terminateEarlyNode(n.getShape())) {
				break;
			}
			r = visit(node, n, query, visitor, ordered);
			if (r == VisitResult.ASCEND) {
				return visitor.endNode(parent, node, inclusion);
			}
			if (r == VisitResult.TERMINATE) {
				visitor.endNode(parent, node, inclusion);
				return r;
			}
		}
		return visitor.endNode(parent, node, inclusion);
	}

	protected Iterator<DR> iterator(Q query) {
		return iterator(root, query);
	}

	protected Iterator<DR> iterator(NR node, Q query) {
		if (node.getType().isLeaf()) {
			List<DR> data = new ArrayList<>(node.getChildCount());
			for (DR d : getDataChildrenOf(node)) {
				if (query != null && !query.testData(d.getShape())) {
					continue;
				}
				data.add(d);
			}
			return data.iterator();
		}
		List<NR> nodes = new ArrayList<>(node.getChildCount());
		for (NR n : getNodeChildrenOf(node)) {
			if (query != null && query.testNode(n.getShape()) == QueryInclusion.NONE) {
				continue;
			}
			nodes.add(n);
		}
		return NestedIterator.start(nodes.iterator(), n -> iterator(n, query));
	}

	protected Iterator<DR> orderedIterator(Q query) {
		return new PeekableIterator<DR>() {
			Comparator<NS> boundsComparator =
				query != null ? query.getBoundsComparator() : getDefaultBoundsComparator();
			Comparator<? super DBTreeRecord<?, ? extends NS>> recordComparator =
				Comparator.comparing(DBTreeRecord::getBounds, boundsComparator);
			PriorityQueue<DBTreeRecord<?, ? extends NS>> queue =
				new PriorityQueue<>(recordComparator);

			{
				descend(root);
			}

			private DR next;
			private boolean soughtNext;

			private void checkSoughtNext() {
				if (!soughtNext) {
					next = findNext();
					soughtNext = true;
				}
			}

			private void descend(NR nr) {
				queue.addAll(getChildrenOf(nr));
			}

			private DR findNext() {
				while (true) {
					DBTreeRecord<?, ? extends NS> rec = queue.poll();
					if (rec == null) {
						return null;
					}
					if (query != null && query.terminateEarlyNode(rec.getBounds())) {
						return null;
					}
					if (rec instanceof DBTreeDataRecord) {
						@SuppressWarnings("unchecked")
						DR dr = (DR) rec;
						if (query != null && !query.testData(dr.getShape())) {
							continue;
						}
						return dr;
					}
					assert rec instanceof DBTreeNodeRecord;
					@SuppressWarnings("unchecked")
					NR nr = (NR) rec;
					if (query != null && query.testNode(nr.getShape()) != QueryInclusion.NONE) {
						descend(nr);
					}
					continue;
				}
			}

			@Override
			public boolean hasNext() {
				checkSoughtNext();
				return next != null;
			}

			@Override
			public DR peek() throws NoSuchElementException {
				checkSoughtNext();
				if (next == null) {
					throw new NoSuchElementException();
				}
				return next;
			}

			@Override
			public DR next() {
				checkSoughtNext();
				soughtNext = false;
				return next;
			}
		};
	}

	protected int count(Q query) {
		var visitor = new TreeRecordVisitor() {
			int count = 0;

			@Override
			protected VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion) {
				if (inclusion == QueryInclusion.NONE) {
					return VisitResult.NEXT;
				}
				if (inclusion == QueryInclusion.ALL) {
					count += n.getDataCount();
					return VisitResult.NEXT;
				}
				return VisitResult.DESCEND;
			}

			@Override
			protected VisitResult visitData(NR parent, DR d, boolean included) {
				if (included) {
					count++;
				}
				return VisitResult.NEXT;
			}
		};
		visit(query, visitor, false);
		return visitor.count;
	}

	protected boolean isEmpty(Q query) {
		var visitor = new TreeRecordVisitor() {
			boolean result = true;

			@Override
			protected VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion) {
				if (inclusion == QueryInclusion.NONE) {
					return VisitResult.NEXT;
				}
				if (inclusion == QueryInclusion.ALL) {
					if (n.getDataCount() > 0) {
						result = false;
						return VisitResult.TERMINATE;
					}
				}
				return VisitResult.DESCEND;
			}

			@Override
			protected VisitResult visitData(NR parent, DR d, boolean included) {
				if (included) {
					result = false;
					return VisitResult.TERMINATE;
				}
				return VisitResult.NEXT;
			}
		};
		visit(query, visitor, false);
		return visitor.result;
	}

	protected DR first(Q query) {
		Comparator<NS> comparator =
			query != null ? query.getBoundsComparator() : getDefaultBoundsComparator();
		var visitor = new TreeRecordVisitor() {
			DR result;

			@Override
			protected VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion) {
				if (result != null && comparator.compare(result.getBounds(), n.getShape()) <= 0) {
					// Assumes iteration is in same order as comparator
					return VisitResult.ASCEND;
				}
				if (inclusion == QueryInclusion.NONE) {
					return VisitResult.NEXT;
				}
				return VisitResult.DESCEND;
			}

			@Override
			protected VisitResult visitData(NR parent, DR d, boolean included) {
				if (result != null) {
					if (comparator.compare(result.getBounds(), d.getBounds()) <= 0) {
						// Assumes iteration is in same order as comparator
						return VisitResult.ASCEND;
					}
				}
				if (included) {
					result = d;
				}
				return VisitResult.NEXT;
			}
		};
		visit(query, visitor, true);
		return visitor.result;
	}

	protected void visitAllData(Q query, Consumer<DR> consumer, boolean ordered) {
		var visitor = new TreeRecordVisitor() {
			@Override
			protected VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion) {
				if (inclusion == QueryInclusion.NONE) {
					return VisitResult.NEXT;
				}
				return VisitResult.DESCEND;
			}

			@Override
			protected VisitResult visitData(NR parent, DR d, boolean included) {
				if (included) {
					consumer.accept(d);
				}
				return VisitResult.NEXT;
			}
		};
		visit(query, visitor, ordered);
	}

	protected DR doFindExact(DS shape, T value, Q query) {
		Comparator<NS> comparator = query == null ? null : query.getBoundsComparator();
		var visitor = new TreeRecordVisitor() {
			DR result;

			@Override
			protected VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion) {
				if (comparator != null && comparator.compare(shape.getBounds(), n.getShape()) < 0) {
					return VisitResult.ASCEND;
				}
				if (inclusion == QueryInclusion.NONE) {
					return VisitResult.NEXT;
				}
				if (!n.getShape().encloses(shape.getBounds())) {
					return VisitResult.NEXT;
				}
				return VisitResult.DESCEND;
			}

			@Override
			protected VisitResult visitData(NR parent, DR d, boolean included) {
				if (comparator != null &&
					comparator.compare(shape.getBounds(), d.getBounds()) <= 0) {
					return VisitResult.ASCEND;
				}
				if (!included) {
					return VisitResult.NEXT;
				}
				if (!d.shapeEquals(shape)) {
					return VisitResult.NEXT;
				}
				if (!value.equals(d.getRecordValue())) {
					return VisitResult.NEXT;
				}
				result = d;
				return VisitResult.TERMINATE;
			}
		};
		visit(query, visitor, false);
		return visitor.result;
	}

	protected void doUpdateOrDeleteAlongPath(NR node) {
		NR cur = node;
		for (; cur != null; cur = getParentOf(cur)) {
			int childCount = cur.getChildCount() - 1;
			if (childCount == 0) {
				doRemoveFromCachedChildren(cur.getParentKey(), cur, cachedNodeChildren);
				nodeStore.delete(cur);
				if (cur == root) {
					root = null;
					// Up to one orphan allowed. 
					assert dataStore.getRecordCount() == 0 || dataStore.getRecordCount() == 1;
					assert nodeStore.getRecordCount() == 0;
					init();
					return;
				}
				continue;
			}
			cur.setChildCount(childCount);
			break;
		}
		for (; cur != null; cur = getParentOf(cur)) {
			doDecrementDataCount(cur);
			doRecomputeBounds(cur);
		}
	}

	protected void doDecrementDataCount(NR node) {
		node.setDataCount(node.getDataCount() - 1);
	}

	protected void doRecomputeBounds(NR node) {
		/*
		 * TODO: There may be optimizations here, esp. if no bound of the removed node is on the
		 * edge of the parent. Furthermore, since an implementation may index on those bounds, there
		 * may be a fast way to discover the "next child in".
		 */
		Collection<? extends NS> childBounds =
			Collections2.transform(getChildrenOf(node), DBTreeRecord::getBounds);
		NS bounds = BoundingShape.boundsUnion(childBounds);
		node.setShape(bounds);
	}

	protected <R> void doRemoveFromCachedChildren(long parentKey, R child,
			Map<Long, Collection<R>> cache) {
		Collection<R> children = cache.get(parentKey);
		if (children == null) {
			return;
		}
		if (!children.remove(child)) {
			throw new AssertionError();
		}
	}

	protected <R> void doAddToCachedChildren(long parentKey, R child,
			Map<Long, Collection<R>> cache) {
		Collection<R> children = cache.get(parentKey);
		if (children == null) {
			return;
		}
		if (!children.add(child)) {
			throw new AssertionError();
		}
	}

	protected <R extends DBTreeRecord<?, ?>> void doSetParentKey(R child, long key,
			Map<Long, Collection<R>> cache) {
		doRemoveFromCachedChildren(child.getParentKey(), child, cache);
		child.setParentKey(key);
		doAddToCachedChildren(key, child, cache);
	}

	/**
	 * Remove a data record from the tree, but keep the orphaned record in the table
	 * 
	 * Note that at most one orphaned record should be in the table at any time, otherwise behavior
	 * is undefined. It is up to the implementor to provide a means of inserting orphaned data
	 * records back into the tree. This is useful for implementations which allow a data record's
	 * shape to be mutated: Orphan the record, adjust its shape, re-insert the orphan.
	 * 
	 * @param data the data record
	 */
	protected void doUnparentEntry(DR data) {
		NR parent = getParentOf(data);
		doSetParentKey(data, -1, cachedDataChildren);
		doUpdateOrDeleteAlongPath(parent);
	}

	protected void doDeleteEntry(DR data) {
		doUnparentEntry(data);
		if (!dataStore.delete(data)) {
			throw new AssertionError();
		}
	}

	protected boolean doRemoveData(DS shape, T value, Q query) {
		DR found = doFindExact(shape, value, query);
		if (found == null) {
			return false;
		}
		doDeleteEntry(found);
		return true;
	}

	protected void destroySubtree(NR node) {
		visit(null, node, null, new TreeRecordVisitor() {
			@Override
			protected VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion) {
				return VisitResult.DESCEND;
			}

			@Override
			protected VisitResult visitData(NR parent, DR d, boolean included) {
				dataStore.delete(d);
				return VisitResult.NEXT;
			}

			@Override
			protected VisitResult endNode(NR parent, NR n, QueryInclusion inclusion) {
				if (n.getType() == NodeType.LEAF) {
					cachedDataChildren.remove(n.getKey());
				}
				else {
					cachedNodeChildren.remove(n.getKey());
				}
				nodeStore.delete(n);
				return VisitResult.NEXT;
			}
		}, false);
	}

	protected void resyncMetadata(NR node) {
		int childCount = 0;
		int dataCount = 0;
		NS bounds = null;
		for (DBTreeRecord<?, ? extends NS> child : getChildrenOf(node)) {
			childCount++;
			dataCount += child.getDataCount();
			bounds = bounds == null ? child.getBounds() : bounds.unionBounds(child.getBounds());
		}
		node.setChildCount(childCount);
		node.setDataCount(dataCount);
		node.setShape(bounds);
	}

	protected void clear(Q query) {
		visit(query, new TreeRecordVisitor() {
			Set<NR> dirty = new HashSet<>();

			@Override
			protected VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion) {
				if (inclusion == QueryInclusion.NONE) {
					return VisitResult.NEXT;
				}
				if (inclusion == QueryInclusion.ALL) {
					if (n == root) {
						cachedDataChildren.clear();
						cachedNodeChildren.clear();
						dataStore.deleteAll();
						nodeStore.deleteAll();
						root = null;
						init();
						return VisitResult.TERMINATE;
					}
					dirty.add(parent);
					doRemoveFromCachedChildren(parent.getKey(), n, cachedNodeChildren);
					destroySubtree(n);
					return VisitResult.NEXT;
				}
				return VisitResult.DESCEND;
			}

			@Override
			protected VisitResult visitData(NR parent, DR d, boolean included) {
				if (!included) {
					return VisitResult.NEXT;
				}
				dirty.add(parent);
				doRemoveFromCachedChildren(parent.getKey(), d, cachedDataChildren);
				dataStore.delete(d);
				return VisitResult.NEXT;
			}

			@Override
			protected VisitResult endNode(NR parent, NR n, QueryInclusion inclusion) {
				if (dirty.remove(n)) {
					resyncMetadata(n);
					dirty.add(parent);
				}
				return VisitResult.NEXT;
			}
		}, false);
	}

	/**
	 * Dump the tree to the console, for debugging and testing purposes
	 * 
	 * @param query optionally include only those portions matching a query
	 */
	protected void dump(Q query) {
		visit(query, new TreeRecordVisitor() {
			String getLevel(DBTreeRecord<?, ?> record) {
				String level = "";
				NR parent = getParentOf(record);
				while (parent != null) {
					level = level + "  ";
					parent = getParentOf(parent);
				}
				return level;
			}

			@Override
			protected VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion) {
				System.out.println(getLevel(n) + n + ": (" + inclusion + ")");
				if (inclusion == QueryInclusion.NONE) {
					return VisitResult.NEXT;
				}
				return VisitResult.DESCEND;
			}

			@Override
			protected VisitResult visitData(NR parent, DR d, boolean included) {
				System.out.println(getLevel(d) + d + ": (" + included + ")");
				return VisitResult.NEXT;
			}
		}, true);
	}

	/**
	 * Check the integrity of a single node entry.
	 * 
	 * This method is for tree developers and testers. Override this method if you have additional
	 * integrity checks.
	 * 
	 * @param n the entry to check
	 */
	protected void checkNodeIntegrity(NR n) {
		// Check parent has exactly the minimum bounds of its children
		Collection<? extends NS> childBounds =
			Collections2.transform(getChildrenOf(n), DBTreeRecord::getBounds);
		NS expectedBounds = BoundingShape.boundsUnion(childBounds);
		if (expectedBounds == null && n != root) {
			throw new AssertionError("Non-root node cannot be empty");
		}
		if (expectedBounds != null && !expectedBounds.equals(n.getBounds())) {
			throw new AssertionError("Parent bounds do not match expected");
		}

		// Check parent type wrt. child types
		switch (n.getType()) {
			case DIRECTORY: {
				Collection<DR> dataChildren = getDataChildrenOf(n.getKey());
				// NOTE: isEmpty() uses size(), which uses getChildCount
				// Has no regard for which table. Use iterator instead.
				if (dataChildren.iterator().hasNext()) {
					throw new AssertionError(
						"Directory node " + n + " cannot contain data " + dataChildren);
				}
				Collection<NR> nodeChildren = getNodeChildrenOf(n);
				if (!nodeChildren.iterator().hasNext()) {
					throw new AssertionError("Directory node " + n + " cannot be empty");
				}
				NodeType childType = nodeChildren.iterator().next().getType();
				if (childType == NodeType.LEAF) {
					throw new AssertionError(
						"Only leaf-parent directory node can have leaf children: n=" + n +
							",children=" + nodeChildren);
				}
				for (NR nr : nodeChildren) {
					if (nr.getType() != childType) {
						throw new AssertionError(
							"All sibling must have the same type: " + nodeChildren);
					}
				}
				break;
			}
			case LEAF_PARENT: {
				Collection<DR> dataChildren = getDataChildrenOf(n);
				if (dataChildren.iterator().hasNext()) {
					throw new AssertionError(
						"Directory node " + n + " cannot contain data " + dataChildren);
				}
				Collection<NR> nodeChildren = getNodeChildrenOf(n);
				if (!nodeChildren.iterator().hasNext()) {
					throw new AssertionError("Leaf-parent " + n + " cannot be empty");
				}
				for (NR nr : nodeChildren) {
					if (nr.getType() != NodeType.LEAF) {
						throw new AssertionError("Leaf-parent node " + n +
							" must have all leaf children: " + nodeChildren);
					}
				}
				break;
			}
			case LEAF:
				Collection<NR> nodeChildren = getNodeChildrenOf(n);
				if (nodeChildren.iterator().hasNext()) {
					throw new AssertionError(
						"Leaf node " + n + " cannot contain nodes " + nodeChildren);
				}
		}

		// Check that child count matches by counting over iterator
		long actualChildCount = 0;
		for (@SuppressWarnings("unused")
		Object obj : getChildrenOf(n)) {
			actualChildCount++;
		}
		if (actualChildCount != n.getChildCount()) {
			throw new AssertionError("Parent's child count " + n.getChildCount() +
				" does not match actual count " + actualChildCount);
		}

		// Check that data count matches by summing over iterator
		long actualDataCount = 0;
		for (DBTreeRecord<?, ?> r : getChildrenOf(n)) {
			actualDataCount += r.getDataCount();
		}
		if (actualDataCount != n.getDataCount()) {
			throw new AssertionError("Parent's data count " + n.getDataCount() +
				" does not match actual sum " + actualDataCount);
		}
	}

	/**
	 * Check the integrity of a single data entry.
	 * 
	 * This method is for tree developers and testers. Override this method if you have additional
	 * integrity checks.
	 * 
	 * @param d the entry to check
	 */
	protected void checkDataIntegrity(DR d) {
		// Extension point
	}

	/**
	 * An integrity checker for use by tree developers and testers.
	 * 
	 * <p>
	 * To incorporate additional checks, please prefer to override
	 * {@link #checkNodeIntegrity(DBTreeNodeRecord)} and/or
	 * {@link #checkDataIntegrity(DBTreeDataRecord)} instead of this method.
	 */
	public void checkIntegrity() {
		// Before we visit, integrity check that cache. Visiting will affect cache.
		for (Entry<Long, Collection<DR>> ent : cachedDataChildren.entrySet()) {
			Set<DR> databasedChildren = new TreeSet<>(Comparator.comparing(DR::getKey));
			// NOTE: Bypass the cache by using the variant with a key parameter
			databasedChildren.addAll(getDataChildrenOf(ent.getKey()));
			Set<DR> cachedChildren = new TreeSet<>(Comparator.comparing(DR::getKey));
			cachedChildren.addAll(ent.getValue());
			if (!databasedChildren.equals(cachedChildren)) {
				throw new AssertionError("Cached children of node " + ent.getKey() +
					" out of sync: cache=" + cachedChildren + " db=" + databasedChildren);
			}
		}
		for (Entry<Long, Collection<NR>> ent : cachedNodeChildren.entrySet()) {
			Set<NR> databasedChildren = new TreeSet<>(Comparator.comparing(NR::getKey));
			// NOTE: Bypass the cache by using the variant with a key parameter
			databasedChildren.addAll(getNodeChildrenOf(ent.getKey()));
			Set<NR> cachedChildren = new TreeSet<>(Comparator.comparing(NR::getKey));
			cachedChildren.addAll(ent.getValue());
			if (!databasedChildren.equals(cachedChildren)) {
				throw new AssertionError("Cached children of node " + ent.getKey() +
					" out of sync: cache=" + cachedChildren + " db=" + databasedChildren);
			}
		}
		if (leafLevel != computeLeafLevel()) {
			throw new AssertionError("Leaf level is incorrect");
		}
		visit(null, new TreeRecordVisitor() {
			@Override
			protected VisitResult beginNode(NR parent, NR n, QueryInclusion inclusion) {
				checkNodeIntegrity(n);
				return VisitResult.DESCEND;
			}

			@Override
			protected VisitResult visitData(NR parent, DR d, boolean included) {
				checkDataIntegrity(d);
				return VisitResult.NEXT;
			}
		}, false);
	}

	public abstract AbstractConstraintsTreeSpatialMap<DS, DR, NS, T, Q> asSpatialMap();

	public DR getDataByKey(long key) {
		return dataStore.getObjectAt(key);
	}

	public <K> DBCachedObjectIndex<K, DR> getUserIndex(Class<K> fieldClass, DBObjectColumn column) {
		return dataStore.getIndex(fieldClass, column);
	}

	public void invalidateCache() {
		try (LockHold hold = LockHold.lock(dataStore.writeLock())) {
			cachedDataChildren.clear();
			cachedNodeChildren.clear();
			dataStore.invalidateCache();
			nodeStore.invalidateCache();
		}
	}
}
