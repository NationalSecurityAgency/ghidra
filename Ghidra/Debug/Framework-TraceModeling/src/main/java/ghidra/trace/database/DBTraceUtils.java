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
package ghidra.trace.database;

import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import db.*;
import generic.RangeMapSetter;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.RefTypeFactory;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.model.Lifespan;
import ghidra.util.database.DBAnnotatedObject;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;

/**
 * Various utilities used for implementing the trace database
 *
 * <p>
 * Some of these are also useful from the API perspective. TODO: We should probably separate trace
 * API utilities into another class.
 */
public enum DBTraceUtils {
	;

	/**
	 * A tuple used to index/locate a block in the trace's byte stores (memory manager)
	 */
	public static class OffsetSnap {
		public final long offset;
		public final long snap;

		public OffsetSnap(long offset, long snap) {
			this.offset = offset;
			this.snap = snap;
		}

		@Override
		public String toString() {
			return String.format("%d,%08x", snap, offset);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (!(obj instanceof OffsetSnap)) {
				return false;
			}
			OffsetSnap that = (OffsetSnap) obj;
			if (this.offset != that.offset) {
				return false;
			}
			if (this.snap != that.snap) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			return Objects.hash(offset, snap);
		}

		public boolean isScratch() {
			return Lifespan.isScratch(snap);
		}
	}

	// TODO: Should this be in by default?
	/**
	 * A codec or URLs
	 */
	public static class URLDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<URL, OT, StringField> {
		public URLDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(URL.class, objectType, StringField.class, field, column);
		}

		protected String encode(URL url) {
			if (url == null) {
				return null;
			}
			return url.toString();
		}

		@Override
		public void store(URL value, StringField f) {
			f.setString(encode(value));
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setString(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			try {
				String data = record.getString(column);
				if (data == null) {
					setValue(obj, null);
				}
				else {
					setValue(obj, new URL(data));
				}
			}
			catch (MalformedURLException e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * A codec for language IDs
	 */
	public static class LanguageIDDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<LanguageID, OT, StringField> {

		public LanguageIDDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(LanguageID.class, objectType, StringField.class, field, column);
		}

		@Override
		public void store(LanguageID value, StringField f) {
			f.setString(value == null ? null : value.getIdAsString());
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			LanguageID id = getValue(obj);
			if (id == null) {
				record.setString(column, null);
			}
			else {
				record.setString(column, id.getIdAsString());
			}
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			String id = record.getString(column);
			if (id == null) {
				setValue(obj, null);
			}
			else {
				setValue(obj, new LanguageID(id));
			}
		}
	}

	/**
	 * A codec for compiler spec IDs
	 */
	public static class CompilerSpecIDDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<CompilerSpecID, OT, StringField> {

		public CompilerSpecIDDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(CompilerSpecID.class, objectType, StringField.class, field, column);
		}

		@Override
		public void store(CompilerSpecID value, StringField f) {
			f.setString(value == null ? null : value.getIdAsString());
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			CompilerSpecID id = getValue(obj);
			if (id == null) {
				record.setString(column, null);
			}
			else {
				record.setString(column, id.getIdAsString());
			}
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			String id = record.getString(column);
			if (id == null) {
				setValue(obj, null);
			}
			else {
				setValue(obj, new CompilerSpecID(id));
			}
		}
	}

	/**
	 * A (abstract) codec for the offset-snap tuple
	 */
	public abstract static class AbstractOffsetSnapDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<OffsetSnap, OT, BinaryField> {

		public AbstractOffsetSnapDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(OffsetSnap.class, objectType, BinaryField.class, field, column);
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			OffsetSnap value = getValue(obj);
			if (value == null) {
				record.setBinaryData(column, null);
			}
			else {
				record.setBinaryData(column, encode(value));
			}
		}

		@Override
		public void store(OffsetSnap value, BinaryField f) {
			if (value == null) {
				f.setBinaryData(null);
			}
			else {
				f.setBinaryData(encode(value));
			}
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			byte[] data = record.getBinaryData(column);
			if (data == null) {
				setValue(obj, null);
			}
			else {
				setValue(obj, decode(data));
			}
		}

		protected abstract byte[] encode(OffsetSnap value);

		protected abstract OffsetSnap decode(byte[] arr);
	}

	/**
	 * Codec for storing {@link OffsetSnap}s as {@link BinaryField}s.
	 * 
	 * <p>
	 * Encodes the address space ID followed by the address then the snap.
	 *
	 * @param <OT> the type of the object whose field is encoded/decoded.
	 */
	public static class OffsetThenSnapDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractOffsetSnapDBFieldCodec<OT> {

		public OffsetThenSnapDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(objectType, field, column);
		}

		@Override
		protected byte[] encode(OffsetSnap value) {
			// TODO: Can I avoid allocating one on every store?
			ByteBuffer buf = ByteBuffer.allocate(16);
			buf.putLong(value.offset);
			buf.putLong(value.snap ^ Long.MIN_VALUE);
			return buf.array();
		}

		@Override
		protected OffsetSnap decode(byte[] arr) {
			ByteBuffer buf = ByteBuffer.wrap(arr);
			long offset = buf.getLong();
			long snap = buf.getLong() ^ Long.MIN_VALUE;
			return new OffsetSnap(offset, snap);
		}
	}

	/**
	 * A codec for reference types
	 */
	public static class RefTypeDBFieldCodec<OT extends DBAnnotatedObject>
			extends AbstractDBFieldCodec<RefType, OT, ByteField> {
		public RefTypeDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(RefType.class, objectType, ByteField.class, field, column);
		}

		protected byte encode(RefType value) {
			return value == null ? Byte.MIN_VALUE : value.getValue();
		}

		protected RefType decode(byte enc) {
			return enc == Byte.MIN_VALUE ? null : RefTypeFactory.get(enc);
		}

		@Override
		public void store(RefType value, ByteField f) {
			f.setByteValue(encode(value));
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setByteValue(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			setValue(obj, decode(record.getByteValue(column)));
		}
	}

	/**
	 * A setter which works on ranges of addresses
	 *
	 * @param <E> the type of entry
	 * @param <V> the type of value
	 */
	public static abstract class AddressRangeMapSetter<E, V>
			extends RangeMapSetter<E, Address, AddressRange, V> {
		@Override
		protected int compare(Address d1, Address d2) {
			return d1.compareTo(d2);
		}

		@Override
		protected Address getLower(AddressRange range) {
			return range.getMinAddress();
		}

		@Override
		protected Address getUpper(AddressRange range) {
			return range.getMaxAddress();
		}

		@Override
		protected AddressRange toSpan(Address lower, Address upper) {
			return new AddressRangeImpl(lower, upper);
		}

		@Override
		protected Address getPrevious(Address d) {
			return d.previous();
		}

		@Override
		protected Address getNext(Address d) {
			return d.next();
		}
	}

	/**
	 * A setter which operates on spans of snapshot keys
	 *
	 * @param <E> the type of entry
	 * @param <V> the type of value
	 */
	public static abstract class LifespanMapSetter<E, V>
			extends RangeMapSetter<E, Long, Lifespan, V> {

		@Override
		protected int compare(Long d1, Long d2) {
			return Lifespan.DOMAIN.compare(d1, d2);
		}

		@Override
		protected Long getLower(Lifespan span) {
			return span.min();
		}

		@Override
		protected Long getUpper(Lifespan span) {
			return span.max();
		}

		@Override
		protected Lifespan toSpan(Long lower, Long upper) {
			return Lifespan.span(lower, upper);
		}

		@Override
		protected Long getPrevious(Long d) {
			if (d == null || d == Long.MIN_VALUE) {
				return null;
			}
			return d - 1;
		}

		@Override
		protected Long getNext(Long d) {
			if (d == null || d == Long.MAX_VALUE) {
				return null;
			}
			return d + 1;
		}
	}

	/**
	 * Derive the table name for a given addres/register space
	 * 
	 * @param baseName the base name of the table group
	 * @param space the address space
	 * @param threadKey the thread key, -1 usually indicating "no thread"
	 * @param frameLevel the frame level
	 * @return the table name
	 */
	public static String tableName(String baseName, AddressSpace space, long threadKey,
			int frameLevel) {
		if (space.isRegisterSpace()) {
			if (frameLevel == 0) {
				return baseName + "_" + space.getName() + "_" + threadKey;
			}
			return baseName + "_" + space.getName() + "_" + threadKey + "_" + frameLevel;
		}
		return baseName + "_" + space.getName();
	}

	/**
	 * Truncate or delete an entry to make room
	 * 
	 * <p>
	 * Only call this method for entries which definitely intersect the given span. This does not
	 * verify intersection. If the data's start snap is contained in the span to clear, the entry is
	 * deleted. Otherwise, it's end snap is set to one less than the span's start snap.
	 * 
	 * @param data the entry subject to truncation or deletion
	 * @param span the span to clear up
	 * @param lifespanSetter the method used to truncate the entry
	 * @param deleter the method used to delete the entry
	 */
	public static <DR extends AbstractDBTraceAddressSnapRangePropertyMapData<?>> void makeWay(
			DR data, Lifespan span, BiConsumer<? super DR, Lifespan> lifespanSetter,
			Consumer<? super DR> deleter) {
		// TODO: Not sure I like this rule....
		if (span.contains(data.getY1())) {
			deleter.accept(data);
			return;
		}
		// NOTE: We know it intersects 
		lifespanSetter.accept(data, Lifespan.span(data.getY1(), span.lmin() - 1));
	}

	/**
	 * Cast an iterator to a less-specific type, given that it cannot insert elements
	 * 
	 * @param <T> the desired type
	 * @param it the iterator of more specific type
	 * @return the same iterator
	 */
	@SuppressWarnings("unchecked")
	public static <T> Iterator<T> covariantIterator(Iterator<? extends T> it) {
		// Iterators only support read and remove, not insert. Safe to cast.
		return (Iterator<T>) it;
	}

	/**
	 * Get all the addresses in a factory, starting at the given place
	 * 
	 * <p>
	 * If backward, this yields all addresses coming before start
	 * 
	 * @param factory the factory
	 * @param start the start (or end) address
	 * @param forward true for all after, false for all before
	 * @return the address set
	 */
	public static AddressSetView getAddressSet(AddressFactory factory, Address start,
			boolean forward) {
		AddressSet all = factory.getAddressSet();
		if (forward) {
			Address max = all.getMaxAddress();
			return factory.getAddressSet(start, max);
		}
		Address min = all.getMinAddress();
		return factory.getAddressSet(min, start);
	}

	/**
	 * Create an address range, checking the endpoints
	 * 
	 * @param min the min address, which must be less than or equal to max
	 * @param max the max address, which must be greater than or equal to min
	 * @return the range
	 * @throws IllegalArgumentException if max is less than min
	 */
	public static AddressRange toRange(Address min, Address max) {
		if (min.compareTo(max) > 0) {
			throw new IllegalArgumentException("min must precede max");
		}
		return new AddressRangeImpl(min, max);
	}
}
