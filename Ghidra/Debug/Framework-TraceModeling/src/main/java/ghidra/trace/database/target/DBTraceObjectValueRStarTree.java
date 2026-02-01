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
import java.util.Collection;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Predicate;

import db.DBRecord;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.database.target.ValueSpace.AddressDimension;
import ghidra.trace.database.target.ValueSpace.EntryKeyDimension;
import ghidra.trace.model.Lifespan;
import ghidra.util.database.*;
import ghidra.util.database.spatial.AbstractConstraintsTree;
import ghidra.util.database.spatial.hyper.AbstractHyperRStarTree;
import ghidra.util.database.spatial.hyper.EuclideanHyperSpace;
import ghidra.util.exception.VersionException;

public class DBTraceObjectValueRStarTree extends AbstractHyperRStarTree< //
		ValueTriple, //
		ValueShape, DBTraceObjectValueData, //
		ValueBox, DBTraceObjectValueNode, //
		DBTraceObjectValueData, TraceObjectValueQuery> {

	public static class DBTraceObjectValueMap extends AsSpatialMap<ValueShape, //
			DBTraceObjectValueData, ValueBox, DBTraceObjectValueData, TraceObjectValueQuery> {

		private final AddressFactory factory;
		private final ReadWriteLock lock;

		public DBTraceObjectValueMap(AbstractConstraintsTree<ValueShape, DBTraceObjectValueData, //
				ValueBox, ?, DBTraceObjectValueData, TraceObjectValueQuery> tree,
				TraceObjectValueQuery query, AddressFactory factory, ReadWriteLock lock) {
			super(tree, query);
			this.factory = factory;
			this.lock = lock;
		}

		@Override
		public DBTraceObjectValueMap reduce(TraceObjectValueQuery andQuery) {
			return new DBTraceObjectValueMap(this.tree,
				this.query == null ? andQuery : this.query.and(andQuery), this.factory, this.lock);
		}

		public AddressSetView getAddressSetView(Lifespan at,
				Predicate<? super DBTraceObjectValueData> predicate) {
			return new DBTraceObjectValueMapAddressSetView(factory, lock,
				this.reduce(TraceObjectValueQuery.intersecting(
					EntryKeyDimension.INSTANCE.absoluteMin(),
					EntryKeyDimension.INSTANCE.absoluteMax(),
					at,
					AddressDimension.INSTANCE.absoluteMin(),
					AddressDimension.INSTANCE.absoluteMax())),
				predicate);
		}
	}

	protected final DBTraceObjectManager manager;
	protected final DBCachedObjectIndex<Long, DBTraceObjectValueNode> nodesByParent;
	protected final DBCachedObjectIndex<Long, DBTraceObjectValueData> dataByParent;

	public DBTraceObjectValueRStarTree(DBTraceObjectManager manager,
			DBCachedObjectStoreFactory storeFactory, String tableName,
			EuclideanHyperSpace<ValueTriple, ValueBox> space,
			Class<DBTraceObjectValueData> dataType, Class<DBTraceObjectValueNode> nodeType,
			boolean upgradeable, int maxChildren) throws VersionException, IOException {
		super(storeFactory, tableName, space, dataType, nodeType, upgradeable, maxChildren);
		this.manager = manager;
		this.nodesByParent = nodeStore.getIndex(long.class, DBTraceObjectValueNode.PARENT_COLUMN);
		this.dataByParent = dataStore.getIndex(long.class, DBTraceObjectValueNode.PARENT_COLUMN);

		init();
	}

	protected DBCachedObjectStore<DBTraceObjectValueData> getDataStore() {
		return dataStore;
	}

	@Override
	protected void doUnparentEntry(DBTraceObjectValueData data) {
		super.doUnparentEntry(data);
	}

	protected void doInsertDataEntry(DBTraceObjectValueData entry) {
		super.doInsert(entry, new LevelInfo(leafLevel));
	}

	@Override
	protected void doDeleteEntry(DBTraceObjectValueData data) {
		super.doDeleteEntry(data);
	}

	@Override
	protected DBTraceObjectValueData createDataEntry(
			DBCachedObjectStore<DBTraceObjectValueData> store, DBRecord record) {
		return new DBTraceObjectValueData(manager, this, store, record);
	}

	@Override
	protected DBTraceObjectValueNode createNodeEntry(
			DBCachedObjectStore<DBTraceObjectValueNode> store, DBRecord record) {
		return new DBTraceObjectValueNode(this, store, record);
	}

	@Override
	protected Collection<DBTraceObjectValueNode> getNodeChildrenOf(long parentKey) {
		return nodesByParent.get(parentKey);
	}

	@Override
	protected Collection<DBTraceObjectValueData> getDataChildrenOf(long parentKey) {
		return dataByParent.get(parentKey);
	}

	@Override
	public DBTraceObjectValueMap asSpatialMap() {
		return new DBTraceObjectValueMap(this, null, manager.trace.getBaseAddressFactory(),
			manager.lock);
	}
}
