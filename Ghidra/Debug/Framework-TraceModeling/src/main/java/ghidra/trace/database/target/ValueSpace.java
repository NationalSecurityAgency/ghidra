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

import java.math.BigInteger;
import java.util.List;

import ghidra.util.database.DBCachedObjectStoreFactory.RecAddress;
import ghidra.util.database.spatial.hyper.*;

enum ValueSpace implements EuclideanHyperSpace<ValueTriple, ValueBox> {
	INSTANCE;

	enum ParentKeyDimension implements ULongDimension<ValueTriple, ValueBox> {
		INSTANCE;

		public static final HyperDirection FORWARD = new HyperDirection(0, true);
		public static final HyperDirection BACKWARD = new HyperDirection(0, false);

		@Override
		public Long value(ValueTriple point) {
			return point.parentKey();
		}
	}

	enum ChildKeyDimension implements ULongDimension<ValueTriple, ValueBox> {
		INSTANCE;

		public static final HyperDirection FORWARD = new HyperDirection(1, true);
		public static final HyperDirection BACKWARD = new HyperDirection(1, false);

		@Override
		public Long value(ValueTriple point) {
			return point.childKey();
		}
	}

	enum EntryKeyDimension implements StringDimension<ValueTriple, ValueBox> {
		INSTANCE;

		public static final HyperDirection FORWARD = new HyperDirection(2, true);
		public static final HyperDirection BACKWARD = new HyperDirection(2, false);

		@Override
		public String value(ValueTriple point) {
			return point.entryKey();
		}
	}

	enum SnapDimension implements LongDimension<ValueTriple, ValueBox> {
		INSTANCE;

		public static final HyperDirection FORWARD = new HyperDirection(3, true);
		public static final HyperDirection BACKWARD = new HyperDirection(3, false);

		@Override
		public Long value(ValueTriple point) {
			return point.snap();
		}
	}

	enum AddressDimension implements Dimension<RecAddress, ValueTriple, ValueBox> {
		INSTANCE;

		static final BigInteger MASK_32 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
		static final BigInteger MASK_64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

		public static final HyperDirection FORWARD = new HyperDirection(4, true);
		public static final HyperDirection BACKWARD = new HyperDirection(4, false);

		@Override
		public RecAddress value(ValueTriple point) {
			return point.address();
		}

		@Override
		public int compare(RecAddress a, RecAddress b) {
			int c = Integer.compareUnsigned(a.spaceId(), b.spaceId());
			if (c != 0) {
				return c;
			}
			return Long.compareUnsigned(a.offset(), b.offset());
		}

		@Override
		public double distance(RecAddress a, RecAddress b) {
			double result = b.spaceId() - a.spaceId();
			result *= Math.pow(2, 64);
			result += (b.offset() - a.offset());
			return result;
		}

		static BigInteger addrToBigInt(RecAddress a) {
			return BigInteger.valueOf(a.spaceId())
					.and(MASK_32)
					.shiftLeft(64)
					.add(BigInteger.valueOf(a.offset()).and(MASK_64));
		}

		static RecAddress bigIntToAddr(BigInteger i) {
			return new RecAddress(i.shiftRight(64).intValue(), i.longValue());
		}

		@Override
		public RecAddress mid(RecAddress a, RecAddress b) {
			BigInteger biA = addrToBigInt(a);
			BigInteger biB = addrToBigInt(b);
			BigInteger biMid = biA.add((biB.subtract(biA)).shiftRight(1));
			return bigIntToAddr(biMid);
		}

		private static final RecAddress MIN = new RecAddress(0, 0);
		private static final RecAddress MAX = new RecAddress(-1, -1);

		@Override
		public RecAddress absoluteMin() {
			return MIN;
		}

		@Override
		public RecAddress absoluteMax() {
			return MAX;
		}
	}

	static final List<Dimension<?, ValueTriple, ValueBox>> DIMENSIONS = List.of(
		ParentKeyDimension.INSTANCE,
		ChildKeyDimension.INSTANCE,
		EntryKeyDimension.INSTANCE,
		SnapDimension.INSTANCE,
		AddressDimension.INSTANCE);

	static final ValueBox FULL = new ImmutableValueBox(
		new ValueTriple(
			ParentKeyDimension.INSTANCE.absoluteMin(),
			ChildKeyDimension.INSTANCE.absoluteMin(),
			EntryKeyDimension.INSTANCE.absoluteMin(),
			SnapDimension.INSTANCE.absoluteMin(),
			AddressDimension.INSTANCE.absoluteMin()),
		new ValueTriple(
			ParentKeyDimension.INSTANCE.absoluteMax(),
			ChildKeyDimension.INSTANCE.absoluteMax(),
			EntryKeyDimension.INSTANCE.absoluteMax(),
			SnapDimension.INSTANCE.absoluteMax(),
			AddressDimension.INSTANCE.absoluteMax()));

	@Override
	public List<Dimension<?, ValueTriple, ValueBox>> getDimensions() {
		return DIMENSIONS;
	}

	@Override
	public ValueBox getFull() {
		return FULL;
	}

	@Override
	public ValueTriple boxCenter(ValueBox box) {
		return new ValueTriple(
			ParentKeyDimension.INSTANCE.boxMid(box),
			ChildKeyDimension.INSTANCE.boxMid(box),
			EntryKeyDimension.INSTANCE.boxMid(box),
			SnapDimension.INSTANCE.boxMid(box),
			AddressDimension.INSTANCE.boxMid(box));
	}

	@Override
	public ValueBox boxUnionBounds(ValueBox a, ValueBox b) {
		ValueTriple lc = new ValueTriple(
			ParentKeyDimension.INSTANCE.unionLower(a, b),
			ChildKeyDimension.INSTANCE.unionLower(a, b),
			EntryKeyDimension.INSTANCE.unionLower(a, b),
			SnapDimension.INSTANCE.unionLower(a, b),
			AddressDimension.INSTANCE.unionLower(a, b));
		ValueTriple uc = new ValueTriple(
			ParentKeyDimension.INSTANCE.unionUpper(a, b),
			ChildKeyDimension.INSTANCE.unionUpper(a, b),
			EntryKeyDimension.INSTANCE.unionUpper(a, b),
			SnapDimension.INSTANCE.unionUpper(a, b),
			AddressDimension.INSTANCE.unionUpper(a, b));
		return new ImmutableValueBox(lc, uc);
	}

	@Override
	public ValueBox boxIntersection(ValueBox a, ValueBox b) {
		ValueTriple lc = new ValueTriple(
			ParentKeyDimension.INSTANCE.intersectionLower(a, b),
			ChildKeyDimension.INSTANCE.intersectionLower(a, b),
			EntryKeyDimension.INSTANCE.intersectionLower(a, b),
			SnapDimension.INSTANCE.intersectionLower(a, b),
			AddressDimension.INSTANCE.intersectionLower(a, b));
		ValueTriple uc = new ValueTriple(
			ParentKeyDimension.INSTANCE.intersectionUpper(a, b),
			ChildKeyDimension.INSTANCE.intersectionUpper(a, b),
			EntryKeyDimension.INSTANCE.intersectionUpper(a, b),
			SnapDimension.INSTANCE.intersectionUpper(a, b),
			AddressDimension.INSTANCE.intersectionUpper(a, b));
		return new ImmutableValueBox(lc, uc);
	}
}
