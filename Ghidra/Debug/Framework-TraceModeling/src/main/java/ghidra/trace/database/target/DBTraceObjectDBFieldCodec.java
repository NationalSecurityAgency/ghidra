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

import java.lang.reflect.Field;

import db.DBRecord;
import db.LongField;
import ghidra.util.database.DBAnnotatedObject;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;

public class DBTraceObjectDBFieldCodec<OV extends DBAnnotatedObject & TraceObjectValueStorage>
		extends AbstractDBFieldCodec<DBTraceObject, OV, LongField> {
	public DBTraceObjectDBFieldCodec(Class<OV> objectType, Field field, int column) {
		super(DBTraceObject.class, objectType, LongField.class, field, column);
	}

	protected static long encode(DBTraceObject value) {
		return value == null ? -1 : value.getKey();
	}

	protected static DBTraceObject decode(TraceObjectValueStorage ent, long enc) {
		return enc == -1 ? null : ent.getManager().getObjectById(enc);
	}

	@Override
	public void store(DBTraceObject value, LongField f) {
		f.setLongValue(encode(value));
	}

	@Override
	protected void doStore(OV obj, DBRecord record)
			throws IllegalArgumentException, IllegalAccessException {
		record.setLongValue(column, encode(getValue(obj)));
	}

	@Override
	protected void doLoad(OV obj, DBRecord record)
			throws IllegalArgumentException, IllegalAccessException {
		setValue(obj, decode(obj, record.getLongValue(column)));
	}
}
