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
import ghidra.util.database.DBAnnotatedObject;
import ghidra.util.database.DBCachedObjectStore;

public abstract class DBTreeRecord<RS extends BoundedShape<NS>, NS extends BoundingShape<NS>>
		extends DBAnnotatedObject {
	public DBTreeRecord(DBCachedObjectStore<?> store, DBRecord record) {
		super(store, record);
	}

	public abstract RS getShape();

	public abstract NS getBounds();

	public abstract void setShape(RS shape);

	public abstract long getParentKey();

	public abstract void setParentKey(long parentKey);

	/**
	 * Get the total number of data entries in this sub-tree
	 * 
	 * For data entries, this is 1.
	 * 
	 * @return the data count
	 */
	protected abstract int getDataCount();
}
