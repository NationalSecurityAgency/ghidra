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

import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.target.ValueSpace.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.util.database.DBCachedObjectStoreFactory.RecAddress;
import ghidra.util.database.spatial.hyper.AbstractHyperBoxQuery;
import ghidra.util.database.spatial.hyper.HyperDirection;

public class TraceObjectValueQuery
		extends AbstractHyperBoxQuery<ValueTriple, ValueShape, ValueBox, TraceObjectValueQuery> {

	public TraceObjectValueQuery(ValueBox ls, ValueBox us, HyperDirection direction) {
		super(ls, us, ls.space(), direction);
	}

	@Override
	public boolean testData(ValueShape shape) {
		ValueBox bounds = shape.getBounds();
		if (!ls.contains(bounds.lCorner())) {
			return false;
		}
		if (!us.contains(bounds.uCorner())) {
			return false;
		}
		return true;
	}

	@Override
	protected TraceObjectValueQuery create(ValueBox ir1, ValueBox ir2,
			HyperDirection newDirection) {
		return new TraceObjectValueQuery(ir1, ir2, newDirection);
	}

	public static TraceObjectValueQuery all() {
		return AbstractHyperBoxQuery.intersecting(ValueSpace.FULL, HyperDirection.DEFAULT,
			TraceObjectValueQuery::new);
	}

	public static TraceObjectValueQuery canonicalParents(DBTraceObject child, Lifespan lifespan) {
		Objects.requireNonNull(child);
		TraceObjectKeyPath path = child.getCanonicalPath();
		String entryKey = path.isRoot() ? "" : path.key();
		long childKey = child.getKey();
		return AbstractHyperBoxQuery.intersecting(
			new ImmutableValueBox(
				new ValueTriple(
					ParentKeyDimension.INSTANCE.absoluteMin(),
					childKey, entryKey, lifespan.lmin(),
					AddressDimension.INSTANCE.absoluteMin()),
				new ValueTriple(
					ParentKeyDimension.INSTANCE.absoluteMax(),
					childKey, entryKey, lifespan.lmax(),
					AddressDimension.INSTANCE.absoluteMax())),
			HyperDirection.DEFAULT, TraceObjectValueQuery::new);
	}

	public static TraceObjectValueQuery parents(DBTraceObject child, Lifespan lifespan) {
		Objects.requireNonNull(child);
		long childKey = child.getKey();
		return AbstractHyperBoxQuery.intersecting(
			new ImmutableValueBox(
				new ValueTriple(
					ParentKeyDimension.INSTANCE.absoluteMin(),
					childKey,
					EntryKeyDimension.INSTANCE.absoluteMin(),
					lifespan.lmin(),
					AddressDimension.INSTANCE.absoluteMin()),
				new ValueTriple(
					ParentKeyDimension.INSTANCE.absoluteMax(),
					childKey,
					EntryKeyDimension.INSTANCE.absoluteMax(),
					lifespan.lmax(),
					AddressDimension.INSTANCE.absoluteMax())),
			HyperDirection.DEFAULT, TraceObjectValueQuery::new);
	}

	public static TraceObjectValueQuery values(DBTraceObject parent, Lifespan lifespan) {
		Objects.requireNonNull(parent);
		long parentKey = parent.getKey();
		return AbstractHyperBoxQuery.intersecting(
			new ImmutableValueBox(
				new ValueTriple(
					parentKey,
					ChildKeyDimension.INSTANCE.absoluteMin(),
					EntryKeyDimension.INSTANCE.absoluteMin(),
					lifespan.lmin(),
					AddressDimension.INSTANCE.absoluteMin()),
				new ValueTriple(
					parentKey,
					ChildKeyDimension.INSTANCE.absoluteMax(),
					EntryKeyDimension.INSTANCE.absoluteMax(),
					lifespan.lmax(),
					AddressDimension.INSTANCE.absoluteMax())),
			HyperDirection.DEFAULT, TraceObjectValueQuery::new);
	}

	public static TraceObjectValueQuery values(DBTraceObject parent, String minKey, String maxKey,
			Lifespan lifespan) {
		Objects.requireNonNull(parent);
		long parentKey = parent.getKey();
		return AbstractHyperBoxQuery.intersecting(
			new ImmutableValueBox(
				new ValueTriple(
					parentKey,
					ChildKeyDimension.INSTANCE.absoluteMin(),
					minKey,
					lifespan.lmin(),
					AddressDimension.INSTANCE.absoluteMin()),
				new ValueTriple(
					parentKey,
					ChildKeyDimension.INSTANCE.absoluteMax(),
					maxKey,
					lifespan.lmax(),
					AddressDimension.INSTANCE.absoluteMax())),
			HyperDirection.DEFAULT, TraceObjectValueQuery::new);
	}

	public static TraceObjectValueQuery intersecting(String minKey, String maxKey,
			Lifespan lifespan, RecAddress minAddress, RecAddress maxAddress) {
		return AbstractHyperBoxQuery.intersecting(
			new ImmutableValueBox(
				new ValueTriple(
					ParentKeyDimension.INSTANCE.absoluteMin(),
					ChildKeyDimension.INSTANCE.absoluteMin(),
					minKey, lifespan.lmin(), minAddress),
				new ValueTriple(
					ParentKeyDimension.INSTANCE.absoluteMax(),
					ChildKeyDimension.INSTANCE.absoluteMax(),
					maxKey, lifespan.lmax(), maxAddress)),
			HyperDirection.DEFAULT, TraceObjectValueQuery::new);
	}

	public static TraceObjectValueQuery intersecting(String minKey, String maxKey,
			Lifespan lifespan, AddressRange range) {
		return intersecting(minKey, maxKey, lifespan,
			RecAddress.fromAddress(range.getMinAddress()),
			RecAddress.fromAddress(range.getMaxAddress()));
	}

	public static TraceObjectValueQuery intersecting(Lifespan lifespan, AddressRange range) {
		return intersecting(EntryKeyDimension.INSTANCE.absoluteMin(),
			EntryKeyDimension.INSTANCE.absoluteMax(), lifespan, range);
	}

	public static TraceObjectValueQuery at(String entryKey, long snap, Address address) {
		return AbstractHyperBoxQuery.intersecting(
			new ImmutableValueBox(
				new ValueTriple(
					ParentKeyDimension.INSTANCE.absoluteMin(),
					ChildKeyDimension.INSTANCE.absoluteMin(),
					entryKey,
					snap,
					RecAddress.fromAddress(address)),
				new ValueTriple(
					ParentKeyDimension.INSTANCE.absoluteMax(),
					ChildKeyDimension.INSTANCE.absoluteMax(),
					entryKey,
					snap,
					RecAddress.fromAddress(address))),
			HyperDirection.DEFAULT, TraceObjectValueQuery::new);
	}
}
