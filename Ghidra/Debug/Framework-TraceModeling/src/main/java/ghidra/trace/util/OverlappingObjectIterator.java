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
package ghidra.trace.util;

import java.util.Iterator;
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.AbstractPeekableIterator;

public class OverlappingObjectIterator<L, R> extends AbstractPeekableIterator<Pair<L, R>> {
	interface Ranger<T> {
		Address getMinAddress(T t);

		Address getMaxAddress(T t);
	}

	public static class AddressRangeRanger implements Ranger<AddressRange> {
		@Override
		public Address getMinAddress(AddressRange t) {
			return t.getMinAddress();
		}

		@Override
		public Address getMaxAddress(AddressRange t) {
			return t.getMaxAddress();
		}
	}

	public static class SnapRangeKeyRanger implements Ranger<Entry<TraceAddressSnapRange, ?>> {
		@Override
		public Address getMinAddress(Entry<TraceAddressSnapRange, ?> t) {
			return t.getKey().getX1();
		}

		@Override
		public Address getMaxAddress(Entry<TraceAddressSnapRange, ?> t) {
			return t.getKey().getX2();
		}
	}

	public static class CodeUnitRanger implements Ranger<CodeUnit> {
		@Override
		public Address getMinAddress(CodeUnit t) {
			return t.getMinAddress();
		}

		@Override
		public Address getMaxAddress(CodeUnit t) {
			return t.getMaxAddress();
		}
	}

	public static final AddressRangeRanger ADDRESS_RANGE = new AddressRangeRanger();
	public static final SnapRangeKeyRanger SNAP_RANGE_KEY = new SnapRangeKeyRanger();
	public static final CodeUnitRanger CODE_UNIT = new CodeUnitRanger();

	private class MyPair extends Pair<L, R> {
		@Override
		public R setValue(R value) {
			throw new UnsupportedOperationException();
		}

		@Override
		public L getLeft() {
			return nextL;
		}

		@Override
		public R getRight() {
			return nextR;
		}
	}

	private final Iterator<? extends L> left;
	private final Ranger<? super L> leftRanger;
	private final Iterator<? extends R> right;
	private final Ranger<? super R> rightRanger;

	private L nextL;
	private R nextR;
	private MyPair pair = new MyPair();

	public OverlappingObjectIterator(Iterator<? extends L> left, Ranger<? super L> leftRanger,
			Iterator<? extends R> right, Ranger<? super R> rightRanger) {
		this.left = left;
		this.leftRanger = leftRanger;
		this.right = right;
		this.rightRanger = rightRanger;
	}

	@Override
	protected Pair<L, R> seekNext() {
		if (nextL != null) {
			assert nextR != null;
			int cmp = leftRanger.getMaxAddress(nextL).compareTo(rightRanger.getMaxAddress(nextR));
			if (cmp <= 0) {
				nextL = null; // Cause left to advance
			}
			if (cmp >= 0) { // Yes, both should advance if max's are equal
				nextR = null; // Cause right to advance
			}
		}
		else {
			assert nextR == null;
		}

		if (nextL == null) {
			if (!left.hasNext()) {
				return null;
			}
			nextL = left.next();
		}
		if (nextR == null) {
			if (!right.hasNext()) {
				return null;
			}
			nextR = right.next();
		}
		while (true) {
			if (leftRanger.getMaxAddress(nextL).compareTo(rightRanger.getMinAddress(nextR)) < 0) {
				if (!left.hasNext()) {
					nextL = null;
					return null;
				}
				nextL = left.next();
				continue;
			}
			if (rightRanger.getMaxAddress(nextR).compareTo(leftRanger.getMinAddress(nextL)) < 0) {
				if (!right.hasNext()) {
					nextR = null;
					return null;
				}
				nextR = right.next();
				continue;
			}
			// Left and right overlap!
			return pair;
		}
	}
}
