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
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Objects;
import java.util.stream.Stream;

import org.apache.commons.lang3.ArrayUtils;

import db.*;
import ghidra.trace.database.target.visitors.TreeTraversal;
import ghidra.trace.database.target.visitors.TreeTraversal.Visitor;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.*;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;
import ghidra.util.database.DBCachedObjectStoreFactory.VariantDBFieldCodec;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceObjectValue extends DBAnnotatedObject implements InternalTraceObjectValue {
	protected static final String TABLE_NAME = "ObjectValue";

	protected static class PrimaryTriple {
		private final DBTraceObject parent;
		private final String key;
		private final long minSnap;

		protected PrimaryTriple(DBTraceObject parent, String key, long minSnap) {
			this.parent = parent;
			this.key = Objects.requireNonNull(key);
			this.minSnap = minSnap;
		}

		@Override
		public String toString() {
			return "<parent=" + parent + ",key=" + key + ",minSnap=" + minSnap + ">";
		}

		public PrimaryTriple withMinSnap(long minSnap) {
			return new PrimaryTriple(parent, key, minSnap);
		}
	}

	public static class PrimaryTripleDBFieldCodec
			extends AbstractDBFieldCodec<PrimaryTriple, DBTraceObjectValue, BinaryField> {
		static final Charset cs = Charset.forName("UTF-8");

		public PrimaryTripleDBFieldCodec(Class<DBTraceObjectValue> objectType, Field field,
				int column) {
			super(PrimaryTriple.class, objectType, BinaryField.class, field, column);
		}

		protected static byte[] encode(PrimaryTriple value) {
			if (value == null) {
				return null;
			}

			byte[] keyBytes = value.key.getBytes(cs);
			ByteBuffer buf = ByteBuffer.allocate(keyBytes.length + 1 + Long.BYTES * 2);

			buf.putLong(DBTraceObjectDBFieldCodec.encode(value.parent) ^ Long.MIN_VALUE);

			buf.put(keyBytes);
			buf.put((byte) 0);

			buf.putLong(value.minSnap ^ Long.MIN_VALUE);

			return buf.array();
		}

		protected static PrimaryTriple decode(DBTraceObjectValue ent, byte[] enc) {
			if (enc == null) {
				return null;
			}
			ByteBuffer buf = ByteBuffer.wrap(enc);

			DBTraceObject parent =
				DBTraceObjectDBFieldCodec.decode(ent, buf.getLong() ^ Long.MIN_VALUE);

			int nullPos = ArrayUtils.indexOf(enc, (byte) 0, buf.position());
			assert nullPos != -1;
			String key = new String(enc, buf.position(), nullPos - buf.position(), cs);
			buf.position(nullPos + 1);

			long minSnap = buf.getLong() ^ Long.MIN_VALUE;

			return new PrimaryTriple(parent, key, minSnap);
		}

		@Override
		public void store(PrimaryTriple value, BinaryField f) {
			f.setBinaryData(encode(value));
		}

		@Override
		protected void doStore(DBTraceObjectValue obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setBinaryData(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(DBTraceObjectValue obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			setValue(obj, decode(obj, record.getBinaryData(column)));
		}
	}

	public static class DBTraceObjectDBFieldCodec<OV extends DBAnnotatedObject & InternalTraceObjectValue>
			extends AbstractDBFieldCodec<DBTraceObject, OV, LongField> {
		public DBTraceObjectDBFieldCodec(Class<OV> objectType, Field field,
				int column) {
			super(DBTraceObject.class, objectType, LongField.class, field, column);
		}

		protected static long encode(DBTraceObject value) {
			return value == null ? -1 : value.getKey();
		}

		protected static DBTraceObject decode(InternalTraceObjectValue ent, long enc) {
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

	static final String TRIPLE_COLUMN_NAME = "Triple";
	static final String MAX_SNAP_COLUMN_NAME = "MaxSnap";
	static final String CHILD_COLUMN_NAME = "Child";
	static final String PRIMITIVE_COLUMN_NAME = "Primitive";

	@DBAnnotatedColumn(TRIPLE_COLUMN_NAME)
	static DBObjectColumn TRIPLE_COLUMN;
	@DBAnnotatedColumn(MAX_SNAP_COLUMN_NAME)
	static DBObjectColumn MAX_SNAP_COLUMN;
	@DBAnnotatedColumn(CHILD_COLUMN_NAME)
	static DBObjectColumn CHILD_COLUMN;
	@DBAnnotatedColumn(PRIMITIVE_COLUMN_NAME)
	static DBObjectColumn PRIMITIVE_COLUMN;

	@DBAnnotatedField(
		column = TRIPLE_COLUMN_NAME,
		indexed = true,
		codec = PrimaryTripleDBFieldCodec.class)
	private PrimaryTriple triple;
	@DBAnnotatedField(
		column = MAX_SNAP_COLUMN_NAME)
	private long maxSnap;
	@DBAnnotatedField(
		column = CHILD_COLUMN_NAME,
		indexed = true,
		codec = DBTraceObjectDBFieldCodec.class)
	private DBTraceObject child;
	@DBAnnotatedField(
		column = PRIMITIVE_COLUMN_NAME,
		codec = VariantDBFieldCodec.class)
	private Object primitive;

	protected final DBTraceObjectManager manager;

	private Lifespan lifespan;

	public DBTraceObjectValue(DBTraceObjectManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		if (created) {
			return;
		}
		lifespan = Lifespan.span(triple.minSnap, maxSnap);
	}

	protected void set(Lifespan lifespan, DBTraceObject parent, String key, Object value) {
		this.triple = new PrimaryTriple(parent, key, lifespan.lmin());
		this.maxSnap = lifespan.lmax();
		this.lifespan = Lifespan.span(triple.minSnap, maxSnap);
		if (value instanceof TraceObject) {
			DBTraceObject child = manager.assertIsMine((TraceObject) value);
			this.child = child;
			this.primitive = null;
		}
		else {
			this.primitive = manager.validatePrimitive(value);
			this.child = null;
		}
		update(TRIPLE_COLUMN, MAX_SNAP_COLUMN, CHILD_COLUMN, PRIMITIVE_COLUMN);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + ": parent=" + triple.parent + ", key=" + triple.key +
			", lifespan=" + getLifespan() + ", value=" + getValue();
	}

	@Override
	public void doSetLifespan(Lifespan lifespan) {
		long minSnap = lifespan.lmin();
		if (this.triple.minSnap != minSnap) {
			this.triple = triple.withMinSnap(minSnap);
			update(TRIPLE_COLUMN);
		}
		this.maxSnap = lifespan.lmax();
		update(MAX_SNAP_COLUMN);
		this.lifespan = Lifespan.span(minSnap, maxSnap);
	}

	@Override
	public Trace getTrace() {
		return manager.trace;
	}

	@Override
	public DBTraceObjectManager getManager() {
		return manager;
	}

	@Override
	public DBTraceObject getParent() {
		return triple == null ? null : triple.parent;
	}

	@Override
	public String getEntryKey() {
		return triple == null ? null : triple.key;
	}

	@Override
	public Object getValue() {
		try (LockHold hold = manager.trace.lockRead()) {
			return child != null ? child : primitive;
		}
	}

	@Override
	public DBTraceObject getChild() {
		return (DBTraceObject) getValue();
	}

	@Override
	public boolean isObject() {
		return child != null;
	}

	@Override
	public DBTraceObject getChildOrNull() {
		return child;
	}

	@Override
	public Lifespan getLifespan() {
		try (LockHold hold = manager.trace.lockRead()) {
			return lifespan;
		}
	}

	@Override
	public void setMinSnap(long minSnap) {
		try (LockHold hold = manager.trace.lockWrite()) {
			setLifespan(Lifespan.span(minSnap, maxSnap));
		}
	}

	@Override
	public long getMinSnap() {
		try (LockHold hold = manager.trace.lockRead()) {
			return triple.minSnap;
		}
	}

	@Override
	public void setMaxSnap(long maxSnap) {
		try (LockHold hold = manager.trace.lockWrite()) {
			setLifespan(Lifespan.span(triple.minSnap, maxSnap));
		}
	}

	@Override
	public long getMaxSnap() {
		try (LockHold hold = manager.trace.lockRead()) {
			return maxSnap;
		}
	}

	protected Stream<? extends TraceObjectValPath> doStreamVisitor(Lifespan span,
			Visitor visitor) {
		return TreeTraversal.INSTANCE.walkValue(visitor, this, span, null);
	}

	protected TraceObjectKeyPath doGetCanonicalPath() {
		if (triple == null || triple.parent == null) {
			return TraceObjectKeyPath.of();
		}
		return triple.parent.getCanonicalPath().extend(triple.key);
	}

	protected boolean doIsCanonical() {
		if (child == null) {
			return false;
		}
		if (triple.parent == null) {
			return true;
		}
		return doGetCanonicalPath().equals(child.getCanonicalPath());
	}

	@Override
	public TraceObjectKeyPath getCanonicalPath() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return doGetCanonicalPath();
		}
	}

	@Override
	public boolean isCanonical() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return doIsCanonical();
		}
	}

	@Override
	public void doDelete() {
		manager.doDeleteEdge(this);
	}

	@Override
	public void delete() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (triple.parent == null) {
				throw new IllegalArgumentException("Cannot delete root value");
			}
			doDeleteAndEmit();
		}
	}

	@Override
	public InternalTraceObjectValue truncateOrDelete(Lifespan span) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (triple.parent == null) {
				throw new IllegalArgumentException("Cannot truncate or delete root value");
			}
			return doTruncateOrDeleteAndEmitLifeChange(span);
		}
	}
}
