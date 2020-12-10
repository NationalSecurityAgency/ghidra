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
package ghidra.trace.database.map;

import java.util.Map.Entry;
import java.util.NoSuchElementException;

import org.apache.commons.lang3.tuple.ImmutablePair;

import com.google.common.collect.Range;

import generic.util.PeekableIterator;
import ghidra.program.model.address.Address;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.database.spatial.rect.Rectangle2DDirection;

public abstract class AbstractDBTraceAddressSnapRangePropertyMapOcclusionIterable<T>
		implements Iterable<Entry<TraceAddressSnapRange, T>> {
	protected final DBTraceAddressSnapRangePropertyMapSpace<T, ?> space;
	protected final TraceAddressSnapRange within;

	public AbstractDBTraceAddressSnapRangePropertyMapOcclusionIterable(
			DBTraceAddressSnapRangePropertyMapSpace<T, ?> space, TraceAddressSnapRange within) {
		this.space = space;
		this.within = within;
	}

	protected abstract Rectangle2DDirection getVerticalDirection();

	/**
	 * Get the vertical range where entries could exist that occlude the given vertical range
	 * 
	 * @param range the given range
	 * @return the range possibly containing entries which occlude the given range
	 */
	protected abstract Range<Long> getOcclusionRange(Range<Long> range);

	@Override
	public PeekableIterator<Entry<TraceAddressSnapRange, T>> iterator() {
		return new PeekableIterator<>() {
			protected Address address = within.getX1();
			protected boolean soughtNext = false;
			protected Entry<TraceAddressSnapRange, T> next = null;;

			private void checkSeekNext() {
				if (soughtNext) {
					return;
				}
				soughtNext = true;
				next = seekNext();
			}

			private Entry<TraceAddressSnapRange, T> seekNext() {
				if (address == null || !within.getRange().contains(address)) {
					return null;
				}
				Entry<TraceAddressSnapRange, T> topAtAddress = space.reduce(
					TraceAddressSnapRangeQuery.intersecting(address, address, within.getY1(),
						within.getY2()).starting(getVerticalDirection())).firstEntry();
				if (topAtAddress == null) {
					Entry<TraceAddressSnapRange, T> nextEntry =
						space.reduce(TraceAddressSnapRangeQuery.intersecting(address,
							within.getX2(), within.getY1(), within.getY2())
								.starting(
									Rectangle2DDirection.LEFTMOST))
								.firstEntry();
					if (nextEntry == null) {
						return null;
					}
					address = nextEntry.getKey().getX1();
					// The leftmost is not necessarily the topmost
					topAtAddress = space.reduce(
						TraceAddressSnapRangeQuery.intersecting(address, address, within.getY1(),
							within.getY2()).starting(getVerticalDirection())).firstEntry();
				}
				// Now, I must check if another entry will occlude it
				Entry<TraceAddressSnapRange, T> occludes = null;
				Range<Long> occlusionRange = getOcclusionRange(topAtAddress.getKey().getLifespan());
				if (occlusionRange != null) {
					occludes = space.reduce(TraceAddressSnapRangeQuery.intersecting(address,
						within.getX2(), within.getY1(), within.getY2()))
							.reduce(
								TraceAddressSnapRangeQuery.intersecting(
									topAtAddress.getKey().getRange(), occlusionRange)
										.starting(
											Rectangle2DDirection.LEFTMOST))
							.firstEntry();
				}
				if (occludes == null) {
					Entry<TraceAddressSnapRange, T> result =
						new ImmutablePair<>(new ImmutableTraceAddressSnapRange( //
							address, topAtAddress.getKey().getX2(), //
							topAtAddress.getKey().getY1(), topAtAddress.getKey().getY2() //
					).intersection(within), topAtAddress.getValue());
					address = topAtAddress.getKey().getX2().next();
					return result;
				}
				Entry<TraceAddressSnapRange, T> result =
					new ImmutablePair<>(new ImmutableTraceAddressSnapRange( //
						address, occludes.getKey().getX1().previous(), //
						topAtAddress.getKey().getY1(), topAtAddress.getKey().getY2() //
				).intersection(within), topAtAddress.getValue());
				address = occludes.getKey().getX1();
				return result;
			}

			@Override
			public boolean hasNext() {
				checkSeekNext();
				return next != null;
			}

			public Entry<TraceAddressSnapRange, T> peek() throws NoSuchElementException {
				checkSeekNext();
				if (next == null) {
					throw new NoSuchElementException();
				}
				return next;
			}

			@Override
			public Entry<TraceAddressSnapRange, T> next() {
				checkSeekNext();
				soughtNext = false;
				return next;
			}
		};
	}
}
