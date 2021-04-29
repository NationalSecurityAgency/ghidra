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

import java.util.Map.Entry;
import java.util.Objects;

import db.DBRecord;
import ghidra.util.database.DBCachedObjectStore;

public abstract class DBTreeDataRecord<DS extends BoundedShape<NS>, NS extends BoundingShape<NS>, T>
		extends DBTreeRecord<DS, NS> {
	protected interface RecordEntry<DS extends BoundedShape<NS>, NS extends BoundingShape<NS>, T>
			extends Entry<DS, T> {
		public DBTreeDataRecord<DS, NS, T> asRecord();

		default boolean doEquals(Object obj) {
			if (!(obj instanceof Entry)) {
				return false;
			}
			@SuppressWarnings("rawtypes") // Let sub-equality handle type checks
			Entry that = (Entry) obj;
			if (!Objects.equals(this.getKey(), that.getKey())) {
				return false;
			}
			if (!Objects.equals(this.getValue(), that.getValue())) {
				return false;
			}
			return true;
		}

		default int doHashCode() {
			return Objects.hashCode(this.getKey()) ^ Objects.hashCode(this.getValue());
		}
	}

	private final RecordEntry<DS, NS, T> entry = new RecordEntry<>() {
		@Override
		public String toString() {
			T value = getValue();
			return String.format("<DataEntry(%d) %s=%s, parentKey=%d>", asRecord().getKey(),
				getShape().description(), value == DBTreeDataRecord.this ? "record" : value,
				getParentKey());
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
		public DS getKey() {
			return DBTreeDataRecord.this.getShape();
		}

		@Override
		public T getValue() {
			return DBTreeDataRecord.this.getRecordValue();
		}

		@Override
		public T setValue(T value) {
			T old = DBTreeDataRecord.this.getRecordValue();
			DBTreeDataRecord.this.setRecordValue(value);
			return old;
		}

		public DBTreeDataRecord<DS, NS, T> asRecord() {
			return DBTreeDataRecord.this;
		}
	};

	public DBTreeDataRecord(DBCachedObjectStore<?> store, DBRecord record) {
		super(store, record);
	}

	protected abstract boolean shapeEquals(DS shape);

	@Override
	public String toString() {
		T value = getRecordValue();
		return String.format("<Data(%d) %s=%s, parentKey=%d>", getKey(), getShape().description(),
			value == this ? "this" : value, getParentKey());
	}

	/**
	 * Set the value of this record
	 * 
	 * Note that the value is sometimes the record itself. In this case, this method expects
	 * {@code value} to be {@code null} and does nothing. See
	 * {@link SpatialMap#put(BoundedShape, Object)} for more details of this pattern.
	 * 
	 * @param value the record's new value
	 */
	protected abstract void setRecordValue(T value);

	/**
	 * Get the value of this record
	 * 
	 * Note that the value is sometimes the record itself, i.e., this method returns {@code this}.
	 * See {@link SpatialMap#put(BoundedShape, Object)} for more details of this pattern.
	 * 
	 * @return the record's value
	 */
	protected abstract T getRecordValue();

	protected RecordEntry<DS, NS, T> asEntry() {
		return entry;
	}

	@Override
	protected int getDataCount() {
		return 1;
	}
}
