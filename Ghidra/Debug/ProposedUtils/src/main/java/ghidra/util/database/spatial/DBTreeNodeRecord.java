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

import db.DBRecord;
import ghidra.util.database.DBCachedObjectStore;

public abstract class DBTreeNodeRecord<NS extends BoundingShape<NS>> extends DBTreeRecord<NS, NS> {
	protected enum NodeType {
		DIRECTORY(true, false) {
			@Override
			public NodeType getParentType() {
				return DIRECTORY;
			}
		},
		LEAF_PARENT(true, true) {
			@Override
			public NodeType getParentType() {
				return DIRECTORY;
			}
		},
		LEAF(false, false) {
			@Override
			public NodeType getParentType() {
				return LEAF_PARENT;
			}
		};

		private final boolean directory;
		private final boolean leafParent;

		NodeType(boolean directory, boolean leafParent) {
			this.directory = directory;
			this.leafParent = leafParent;
		}

		public boolean isDirectory() {
			return directory;
		}

		public boolean isLeafParent() {
			return leafParent;
		}

		public boolean isLeaf() {
			return !directory;
		}

		public abstract NodeType getParentType();
	}

	public DBTreeNodeRecord(DBCachedObjectStore<?> store, DBRecord record) {
		super(store, record);
	}

	@Override
	public String toString() {
		return String.format("<Node(%d,%s) %s, parentKey=%d, children=%d, data=%d>", getKey(),
			getType(), getShape().description(), getParentKey(), getChildCount(), getDataCount());
	}

	protected abstract NodeType getType();

	protected abstract void setType(NodeType type);

	/**
	 * Get the number of direct descendants of this node
	 * 
	 * @return the child count
	 */
	protected abstract int getChildCount();

	protected abstract void setChildCount(int childCount);

	protected abstract void setDataCount(int dataCount);
}
