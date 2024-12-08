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
package ghidra.util.database.spatial.hyper;

import java.util.Comparator;

import ghidra.util.database.spatial.BoundedShape;
import ghidra.util.database.spatial.Query;

public abstract class AbstractHyperBoxQuery< //
		P extends HyperPoint, //
		DS extends BoundedShape<NS>, //
		NS extends HyperBox<P, NS>, //
		Q extends AbstractHyperBoxQuery<P, DS, NS, Q>> //
		implements Query<DS, NS> {

	public interface QueryFactory<NS extends HyperBox<?, NS>, Q extends AbstractHyperBoxQuery<?, ?, NS, Q>> {
		Q create(NS ls, NS us, HyperDirection direction);
	}

	protected static <P extends HyperPoint, NS extends HyperBox<P, NS>, //
			Q extends AbstractHyperBoxQuery<P, ?, NS, Q>> Q intersecting(NS shape,
					HyperDirection direction, QueryFactory<NS, Q> factory) {
		HyperBox<P, ?> full = shape.space().getFull();
		NS ls = shape.immutable(full.lCorner(), shape.uCorner());
		NS us = shape.immutable(shape.lCorner(), full.uCorner());
		return factory.create(ls, us, direction);
	}

	protected static <P extends HyperPoint, NS extends HyperBox<P, NS>, //
			Q extends AbstractHyperBoxQuery<P, ?, NS, Q>> Q enclosing(NS shape,
					HyperDirection direction, QueryFactory<NS, Q> factory) {
		HyperBox<P, ?> full = shape.space().getFull();
		NS ls = shape.immutable(full.lCorner(), shape.lCorner());
		NS us = shape.immutable(shape.uCorner(), full.uCorner());
		return factory.create(ls, us, direction);
	}

	protected static <P extends HyperPoint, NS extends HyperBox<P, NS>, //
			Q extends AbstractHyperBoxQuery<P, ?, NS, Q>> Q enclosed(NS shape,
					HyperDirection direction, QueryFactory<NS, Q> factory) {
		HyperBox<P, ?> full = shape.space().getFull();
		NS ls = shape.immutable(shape.lCorner(), full.uCorner());
		NS us = shape.immutable(full.lCorner(), shape.uCorner());
		return factory.create(ls, us, direction);
	}

	protected static <P extends HyperPoint, NS extends HyperBox<P, NS>, //
			Q extends AbstractHyperBoxQuery<P, ?, NS, Q>> Q equalTo(NS shape,
					HyperDirection direction, QueryFactory<NS, Q> factory) {
		NS ls = shape.immutable(shape.lCorner(), shape.lCorner());
		NS us = shape.immutable(shape.uCorner(), shape.uCorner());
		return factory.create(ls, us, direction);
	}

	protected final NS ls;
	protected final NS us;
	protected final EuclideanHyperSpace<P, NS> space;
	protected final HyperDirection direction;

	protected Comparator<NS> comparator;

	public AbstractHyperBoxQuery(NS ls, NS us, EuclideanHyperSpace<P, NS> space,
			HyperDirection direction) {
		this.ls = ls;
		this.us = us;
		this.space = space;
		this.direction = direction;
	}

	@Override
	public boolean terminateEarlyData(DS shape) {
		return terminateEarlyNode(shape.getBounds());
	}

	private <T> boolean dimTerminateEarlyNode(Dimension<T, P, NS> dim, NS shape) {
		return direction.forward()
				? dim.compare(dim.lower(shape), dim.upper(us)) > 0
				: dim.compare(dim.upper(shape), dim.lower(ls)) < 0;
	}

	@Override
	public boolean terminateEarlyNode(NS shape) {
		Dimension<?, P, NS> dim = space.getDimensions().get(direction.dimension());
		return dimTerminateEarlyNode(dim, shape);
	}

	@Override
	public Comparator<NS> getBoundsComparator() {
		if (comparator == null) {
			Dimension<?, P, NS> dim = space.getDimensions().get(direction.dimension());
			comparator = createBoundsComparator(dim);
		}
		return comparator;
	}

	protected <T> Comparator<NS> createBoundsComparator(Dimension<T, P, NS> dim) {
		if (direction.forward()) {
			return Comparator.comparing(dim::lower, dim::compare);
		}
		return Comparator.comparing(dim::upper, (a, b) -> dim.compare(b, a));
	}

	private <T> boolean isNone(Dimension<T, P, NS> dim, NS shape) {
		if (dim.compare(dim.lower(shape), dim.upper(ls)) > 0) {
			return true;
		}
		if (dim.compare(dim.lower(shape), dim.upper(us)) > 0) {
			return true;
		}
		if (dim.compare(dim.upper(shape), dim.lower(us)) < 0) {
			return true;
		}
		if (dim.compare(dim.upper(shape), dim.lower(ls)) < 0) {
			return true;
		}
		return false;
	}

	private <T> boolean isSome(Dimension<T, P, NS> dim, NS shape) {
		if (dim.compare(dim.lower(shape), dim.lower(ls)) < 0) {
			return true;
		}
		if (dim.compare(dim.lower(shape), dim.lower(us)) < 0) {
			return true;
		}
		if (dim.compare(dim.upper(shape), dim.upper(us)) > 0) {
			return true;
		}
		if (dim.compare(dim.upper(shape), dim.upper(ls)) > 0) {
			return true;
		}
		return false;
	}

	@Override
	public QueryInclusion testNode(NS shape) {
		for (Dimension<?, P, NS> dim : space.getDimensions()) {
			if (isNone(dim, shape)) {
				return QueryInclusion.NONE;
			}
		}
		for (Dimension<?, P, NS> dim : space.getDimensions()) {
			if (isSome(dim, shape)) {
				return QueryInclusion.SOME;
			}
		}
		return QueryInclusion.ALL;
	}

	protected abstract Q create(NS ir1, NS ir2, HyperDirection newDirection);

	public Q and(Q query) {
		NS ir1 = ls.intersection(query.ls);
		NS ir2 = us.intersection(query.us);
		return create(ir1, ir2, query.direction != null ? query.direction : this.direction);
	}

	public HyperDirection getDirection() {
		if (direction == null) {
			return new HyperDirection(0, true);
		}
		return direction;
	}

	public Q starting(HyperDirection newDirection) {
		return create(ls, us, newDirection);
	}
}
