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
import java.util.*;
import java.util.Map.Entry;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.google.common.collect.*;

import db.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.RefTypeFactory;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
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
			return DBTraceUtils.isScratch(snap);
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
	 * A method outline for setting an entry in a range map where coalescing is desired
	 *
	 * @param <E> the type of entries
	 * @param <D> the type of range bounds
	 * @param <R> the type of ranges
	 * @param <V> the type of values
	 */
	public static abstract class RangeMapSetter<E, D extends Comparable<D>, R, V> {
		/**
		 * Get the range of the given entry
		 * 
		 * @param entry the entry
		 * @return the range
		 */
		protected abstract R getRange(E entry);

		/**
		 * Get the value of the given entry
		 * 
		 * @param entry the entry
		 * @return the value
		 */
		protected abstract V getValue(E entry);

		/**
		 * Remove an entry from the map
		 * 
		 * @param entry the entry
		 */
		protected abstract void remove(E entry);

		/**
		 * Get the lower bound of the range
		 * 
		 * @param range the range
		 * @return the lower bound
		 */
		protected abstract D getLower(R range);

		/**
		 * Get the upper bound of the range
		 * 
		 * @param range the range
		 * @return the upper bound
		 */
		protected abstract D getUpper(R range);

		/**
		 * Create a closed range with the given bounds
		 * 
		 * @param lower the lower bound
		 * @param upper the upper bound
		 * @return the range
		 */
		protected abstract R toRange(D lower, D upper);

		/**
		 * Get the number immediately preceding the given bound
		 * 
		 * @param d the bound
		 * @return the previous bound, or null if it doesn't exist
		 */
		protected abstract D getPrevious(D d);

		/**
		 * Get the number immediately following the given bound
		 * 
		 * @param d the bound
		 * @return the next bound, or null if it doesn't exist
		 */
		protected abstract D getNext(D d);

		/**
		 * Get all entries intersecting the closed range formed by the given bounds
		 * 
		 * @param lower the lower bound
		 * @param upper the upper bound
		 * @return the intersecting entries
		 */
		protected abstract Iterable<E> getIntersecting(D lower, D upper);

		/**
		 * Place an entry into the map
		 * 
		 * @param range the range of the entry
		 * @param value the value of the entry
		 * @return the new entry (or an existing entry)
		 */
		protected abstract E put(R range, V value);

		/**
		 * Get the previous bound or this same bound, if the previous doesn't exist
		 * 
		 * @param d the bound
		 * @return the previous or same bound
		 */
		protected D getPreviousOrSame(D d) {
			D prev = getPrevious(d);
			if (prev == null) {
				return d;
			}
			return prev;
		}

		/**
		 * Get the next bound or this same bound, if the next doesn't exist
		 * 
		 * @param d the bound
		 * @return the next or same bound
		 */
		protected D getNextOrSame(D d) {
			D next = getNext(d);
			if (next == null) {
				return d;
			}
			return next;
		}

		/**
		 * Check if the two ranges are connected
		 * 
		 * <p>
		 * The ranges are connected if they intersect, or if their bounds abut.
		 * 
		 * @param r1 the first range
		 * @param r2 the second range
		 * @return true if connected
		 */
		protected boolean connects(R r1, R r2) {
			return getPreviousOrSame(getLower(r1)).compareTo(getUpper(r2)) <= 0 ||
				getPreviousOrSame(getLower(r2)).compareTo(getUpper(r1)) <= 0;
		}

		/**
		 * Entry point: Set the given range to the given value, coalescing where possible
		 * 
		 * @param range the range
		 * @param value the value
		 * @return the entry containing the value
		 */
		public E set(R range, V value) {
			return set(getLower(range), getUpper(range), value);
		}

		/**
		 * Entry point: Set the given range to the given value, coalescing where possible
		 * 
		 * @param lower the lower bound
		 * @param upper the upper bound
		 * @param value the value
		 * @return the entry containing the value
		 */
		public E set(D lower, D upper, V value) {
			// Go one out to find abutting ranges, too.
			D prev = getPreviousOrSame(lower);
			D next = getNextOrSame(upper);
			Map<R, V> toPut = new HashMap<>();
			for (E entry : getIntersecting(prev, next)) {
				R r = getRange(entry);
				boolean precedesMin = getLower(r).compareTo(lower) < 0;
				boolean succeedsMax = getUpper(r).compareTo(upper) > 0;
				boolean sameVal = Objects.equals(getValue(entry), value);
				if (precedesMin && succeedsMax && sameVal) {
					return entry; // The value in this range is already set as specified
				}
				remove(entry);
				if (precedesMin) {
					if (sameVal) {
						lower = getLower(r);
					}
					else {
						toPut.put(toRange(getLower(r), prev), getValue(entry));
					}
				}
				if (succeedsMax) {
					if (sameVal) {
						upper = getUpper(r);
					}
					else {
						toPut.put(toRange(next, getUpper(r)), getValue(entry));
					}
				}
			}
			E result = put(toRange(lower, upper), value);
			assert toPut.size() <= 2;
			for (Entry<R, V> ent : toPut.entrySet()) {
				put(ent.getKey(), ent.getValue());
			}
			return result;
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
		protected Address getLower(AddressRange range) {
			return range.getMinAddress();
		}

		@Override
		protected Address getUpper(AddressRange range) {
			return range.getMaxAddress();
		}

		@Override
		protected AddressRange toRange(Address lower, Address upper) {
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
			extends RangeMapSetter<E, Long, Range<Long>, V> {

		@Override
		protected Long getLower(Range<Long> range) {
			return lowerEndpoint(range);
		}

		@Override
		protected Long getUpper(Range<Long> range) {
			return upperEndpoint(range);
		}

		@Override
		protected Range<Long> toRange(Long lower, Long upper) {
			return DBTraceUtils.toRange(lower, upper);
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
	 * Get the lower endpoint as stored in the database
	 * 
	 * <p>
	 * {@link Long#MIN_VALUE} represents no lower bound. Endpoints should always be closed unless
	 * unbounded. If open, it will be converted to closed (at one greater).
	 * 
	 * @param range the range
	 * @return the endpoint
	 */
	public static long lowerEndpoint(Range<Long> range) {
		if (!range.hasLowerBound()) {
			return Long.MIN_VALUE;
		}
		if (range.lowerBoundType() == BoundType.CLOSED) {
			return range.lowerEndpoint().longValue();
		}
		return range.lowerEndpoint().longValue() + 1;
	}

	/**
	 * Get the upper endpoint as stored in the database
	 * 
	 * <p>
	 * {@link Long#MAX_VALUE} represents no upper bound. Endpoints should alwyas be closed unless
	 * unbounded. If open, it will be converted to closed (at one less).
	 * 
	 * @param range the range
	 * @return the endpoint
	 */
	public static long upperEndpoint(Range<Long> range) {
		if (!range.hasUpperBound()) {
			return Long.MAX_VALUE;
		}
		if (range.upperBoundType() == BoundType.CLOSED) {
			return range.upperEndpoint().longValue();
		}
		return range.upperEndpoint().longValue() - 1;
	}

	/**
	 * Convert the given enpoints to a range
	 * 
	 * @param lowerEndpoint the lower endpoint, where {@link Long#MIN_VALUE} indicates unbounded
	 * @param upperEndpoint the upper endpoint, where {@link Long#MAX_VALUE} indicates unbounded
	 * @return the range
	 */
	public static Range<Long> toRange(long lowerEndpoint, long upperEndpoint) {
		if (lowerEndpoint == Long.MIN_VALUE && upperEndpoint == Long.MAX_VALUE) {
			return Range.all();
		}
		if (lowerEndpoint == Long.MIN_VALUE) {
			return Range.atMost(upperEndpoint);
		}
		if (upperEndpoint == Long.MAX_VALUE) {
			return Range.atLeast(lowerEndpoint);
		}
		return Range.closed(lowerEndpoint, upperEndpoint);
	}

	/**
	 * Create the range starting at the given snap, to infinity
	 * 
	 * @param snap the starting snap
	 * @return the range [snap, +inf)
	 */
	public static Range<Long> toRange(long snap) {
		return toRange(snap, Long.MAX_VALUE);
	}

	/**
	 * Check if the two ranges intersect
	 * 
	 * <p>
	 * This is a bit obtuse in Guava's API, so here's the convenience method
	 * 
	 * @param <T> the type of range endpoints
	 * @param a the first range
	 * @param b the second range
	 * @return true if they intersect
	 */
	public static <T extends Comparable<T>> boolean intersect(Range<T> a, Range<T> b) {
		// Because we're working with a discrete domain, we have to be careful to never use open
		// lower bounds. Otherwise, the following two inputs would cause a true return value when,
		// in fact, the intersection contains no elements: (0, 1], [0, 1).
		return a.isConnected(b) && !a.intersection(b).isEmpty();
	}

	/**
	 * Check if a given snapshot key is designated as scratch space
	 * 
	 * <p>
	 * Conventionally, negative snaps are scratch space.
	 * 
	 * @param snap the snap
	 * @return true if scratch space
	 */
	public static boolean isScratch(long snap) {
		return snap < 0;
	}

	/**
	 * Form a range starting at the given snap that does not traverse both scratch and non-scratch
	 * space
	 * 
	 * @param start the starting snap
	 * @return the range [start,0] if start is in scratch space, or [start, +inf) if start is not in
	 *         scratch space
	 */
	public static Range<Long> atLeastMaybeScratch(long start) {
		if (start < 0) {
			return Range.closed(start, -1L);
		}
		return Range.atLeast(start);
	}

	/**
	 * "Compare" two ranges
	 * 
	 * <p>
	 * This is just to impose a sorting order for display.
	 * 
	 * @param <C> the type of endpoints
	 * @param a the first range
	 * @param b the second range
	 * @return the result as in {@link Comparable#compareTo(Object)}
	 */
	public static <C extends Comparable<C>> int compareRanges(Range<C> a, Range<C> b) {
		int result;
		if (!a.hasLowerBound() && b.hasLowerBound()) {
			return -1;
		}
		if (!b.hasLowerBound() && a.hasLowerBound()) {
			return 1;
		}
		if (a.hasLowerBound()) { // Implies b.hasLowerBound()
			result = a.lowerEndpoint().compareTo(b.lowerEndpoint());
			if (result != 0) {
				return result;
			}
			if (a.lowerBoundType() == BoundType.CLOSED && b.lowerBoundType() == BoundType.OPEN) {
				return -1;
			}
			if (b.lowerBoundType() == BoundType.CLOSED && a.lowerBoundType() == BoundType.OPEN) {
				return 1;
			}
		}

		if (!a.hasUpperBound() && b.hasUpperBound()) {
			return 1;
		}
		if (!b.hasUpperBound() && a.hasUpperBound()) {
			return -1;
		}
		if (a.hasUpperBound()) { // Implies b.hasUpperBound()
			result = a.upperEndpoint().compareTo(b.upperEndpoint());
			if (result != 0) {
				return result;
			}
			if (a.upperBoundType() == BoundType.CLOSED && b.upperBoundType() == BoundType.OPEN) {
				return 1;
			}
			if (b.upperBoundType() == BoundType.CLOSED && a.upperBoundType() == BoundType.OPEN) {
				return -1;
			}
		}
		return 0;
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
			DR data, Range<Long> span, BiConsumer<? super DR, Range<Long>> lifespanSetter,
			Consumer<? super DR> deleter) {
		// TODO: Not sure I like this rule....
		if (span.contains(data.getY1())) {
			deleter.accept(data);
			return;
		}
		// NOTE: We know it intersects 
		lifespanSetter.accept(data, toRange(data.getY1(), lowerEndpoint(span) - 1));
	}

	/**
	 * Sutract two ranges, yielding 0, 1, or 2 ranges
	 * 
	 * @param a the first range
	 * @param b the second range
	 * @return the list of ranges
	 */
	public static List<Range<Long>> subtract(Range<Long> a, Range<Long> b) {
		RangeSet<Long> set = TreeRangeSet.create();
		set.add(a);
		set.remove(b);
		return set.asRanges()
				.stream()
				.map(r -> toRange(lowerEndpoint(r), upperEndpoint(r)))
				.collect(Collectors.toList());
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
	 * Iterate over all the longs contained in a given range
	 * 
	 * @param span the range
	 * @return the iterator
	 */
	public static Iterator<Long> iterateSpan(Range<Long> span) {
		return new Iterator<>() {
			final long end = upperEndpoint(span);
			long val = lowerEndpoint(span);

			@Override
			public boolean hasNext() {
				return val <= end;
			}

			@Override
			public Long next() {
				long next = val;
				val++;
				return next;
			}
		};
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
