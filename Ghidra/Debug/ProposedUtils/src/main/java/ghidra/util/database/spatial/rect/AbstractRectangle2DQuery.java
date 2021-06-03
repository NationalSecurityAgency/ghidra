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
package ghidra.util.database.spatial.rect;

import java.util.Comparator;

import ghidra.util.database.spatial.BoundedShape;
import ghidra.util.database.spatial.Query;

public abstract class AbstractRectangle2DQuery< //
		X, Y, //
		DS extends BoundedShape<NS>, //
		NS extends Rectangle2D<X, Y, NS>, //
		Q extends AbstractRectangle2DQuery<X, Y, DS, NS, Q>> //
		implements Query<DS, NS> {

	public interface QueryFactory<NS extends Rectangle2D<?, ?, NS>, Q extends AbstractRectangle2DQuery<?, ?, ?, NS, Q>> {
		Q create(NS r1, NS r2, Rectangle2DDirection direction);
	}

	protected static <X, Y, NS extends Rectangle2D<X, Y, NS>, Q extends AbstractRectangle2DQuery<X, Y, ?, NS, Q>> Q intersecting(
			NS rect, Rectangle2DDirection direction, QueryFactory<NS, Q> factory) {
		Rectangle2D<X, Y, ?> full = rect.getSpace().getFull();
		NS r1 = rect.immutable(full.getX1(), rect.getX2(), full.getY1(), rect.getY2());
		NS r2 = rect.immutable(rect.getX1(), full.getX2(), rect.getY1(), full.getY2());
		return factory.create(r1, r2, direction);
	}

	protected static <X, Y, NS extends Rectangle2D<X, Y, NS>, Q extends AbstractRectangle2DQuery<X, Y, ?, NS, Q>> Q enclosing(
			NS rect, Rectangle2DDirection direction, QueryFactory<NS, Q> factory) {
		Rectangle2D<X, Y, ?> full = rect.getSpace().getFull();
		NS r1 = rect.immutable(full.getX1(), rect.getX1(), full.getY1(), rect.getY1());
		NS r2 = rect.immutable(rect.getX2(), full.getX2(), rect.getY2(), full.getY2());
		return factory.create(r1, r2, direction);
	}

	protected static <X, Y, NS extends Rectangle2D<X, Y, NS>, Q extends AbstractRectangle2DQuery<X, Y, ?, NS, Q>> Q enclosed(
			NS rect, Rectangle2DDirection direction, QueryFactory<NS, Q> factory) {
		Rectangle2D<X, Y, ?> full = rect.getSpace().getFull();
		NS r1 = rect.immutable(rect.getX1(), full.getX2(), rect.getY1(), full.getY2());
		NS r2 = rect.immutable(full.getX1(), rect.getX2(), full.getY1(), rect.getY2());
		return factory.create(r1, r2, direction);
	}

	protected static <X, Y, NS extends Rectangle2D<X, Y, NS>, Q extends AbstractRectangle2DQuery<X, Y, ?, NS, Q>> Q equalTo(
			NS rect, Rectangle2DDirection direction, QueryFactory<NS, Q> factory) {
		NS r1 = rect.immutable(rect.getX1(), rect.getX1(), rect.getY1(), rect.getY1());
		NS r2 = rect.immutable(rect.getX2(), rect.getX2(), rect.getY2(), rect.getY2());
		return factory.create(r1, r2, direction);
	}

	protected final NS r1;
	protected final NS r2;
	protected final EuclideanSpace2D<X, Y> space;
	protected final Rectangle2DDirection direction;

	protected Comparator<NS> comparator;

	public AbstractRectangle2DQuery(NS r1, NS r2, EuclideanSpace2D<X, Y> space,
			Rectangle2DDirection direction) {
		this.r1 = r1;
		this.r2 = r2;
		this.space = space;
		this.direction = direction;
	}

	@Override
	public boolean terminateEarlyData(DS shape) {
		return terminateEarlyNode(shape.getBounds());
	}

	@Override
	public boolean terminateEarlyNode(NS shape) {
		switch (getDirection()) {
			case LEFTMOST:
				return space.compareX(shape.getX1(), r2.getX2()) > 0;
			case RIGHTMOST:
				return space.compareX(shape.getX2(), r1.getX1()) < 0;
			case BOTTOMMOST:
				return space.compareY(shape.getY1(), r2.getY2()) > 0;
			case TOPMOST:
				return space.compareY(shape.getY2(), r1.getY1()) < 0;
		}
		throw new AssertionError();
	}

	@Override
	public Comparator<NS> getBoundsComparator() {
		if (comparator == null) {
			comparator = createBoundsComparator();
		}
		return comparator;
	}

	protected Comparator<NS> createBoundsComparator() {
		switch (getDirection()) {
			case LEFTMOST:
				return Comparator.comparing(Rectangle2D::getX1, space::compareX);
			case RIGHTMOST:
				return Comparator.comparing(Rectangle2D::getX2, (a, b) -> space.compareX(b, a));
			case BOTTOMMOST:
				return Comparator.comparing(Rectangle2D::getY1, space::compareY);
			case TOPMOST:
				return Comparator.comparing(Rectangle2D::getY2, (a, b) -> space.compareY(b, a));
		}
		throw new AssertionError();
	}

	@Override
	public QueryInclusion testNode(NS shape) {
		// NOTE: e.g., x2 forms a bound of child x2 /and/ x1
		// That is why we use both r1 and r2 as bounds on both x1,y1 and x2,y2

		// Check inner bounds to see if shape is too small
		// Smaller data shapes in sub-tree cannot satisfy query
		if (space.compareX(shape.getX1(), r1.getX2()) > 0) {
			return QueryInclusion.NONE;
		}
		if (space.compareX(shape.getX1(), r2.getX2()) > 0) {
			return QueryInclusion.NONE;
		}

		if (space.compareY(shape.getY1(), r1.getY2()) > 0) {
			return QueryInclusion.NONE;
		}
		if (space.compareY(shape.getY1(), r2.getY2()) > 0) {
			return QueryInclusion.NONE;
		}

		if (space.compareX(shape.getX2(), r2.getX1()) < 0) {
			return QueryInclusion.NONE;
		}
		if (space.compareX(shape.getX2(), r1.getX1()) < 0) {
			return QueryInclusion.NONE;
		}

		if (space.compareY(shape.getY2(), r2.getY1()) < 0) {
			return QueryInclusion.NONE;
		}
		if (space.compareY(shape.getY2(), r1.getY1()) < 0) {
			return QueryInclusion.NONE;
		}
		// Check outer bounds to see if shape is too big
		// Smaller data shapes in sub-tree may satisfy query
		if (space.compareX(shape.getX1(), r1.getX1()) < 0) {
			return QueryInclusion.SOME;
		}
		if (space.compareX(shape.getX1(), r2.getX1()) < 0) {
			return QueryInclusion.SOME;
		}

		if (space.compareY(shape.getY1(), r1.getY1()) < 0) {
			return QueryInclusion.SOME;
		}
		if (space.compareY(shape.getY1(), r2.getY1()) < 0) {
			return QueryInclusion.SOME;
		}

		if (space.compareX(shape.getX2(), r2.getX2()) > 0) {
			return QueryInclusion.SOME;
		}
		if (space.compareX(shape.getX2(), r1.getX2()) > 0) {
			return QueryInclusion.SOME;
		}

		if (space.compareY(shape.getY2(), r2.getY2()) > 0) {
			return QueryInclusion.SOME;
		}
		if (space.compareY(shape.getY2(), r1.getY2()) > 0) {
			return QueryInclusion.SOME;
		}
		// At this point, we know all smaller children must satisfy the query
		return QueryInclusion.ALL;
	}

	protected abstract Q create(NS ir1, NS ir2, Rectangle2DDirection newDirection);

	public Q and(Q query) {
		NS ir1 = r1.intersection(query.r1);
		NS ir2 = r2.intersection(query.r2);
		return create(ir1, ir2, query.direction != null ? query.direction : this.direction);
	}

	public Rectangle2DDirection getDirection() {
		if (direction == null) {
			return Rectangle2DDirection.LEFTMOST;
		}
		return direction;
	}

	public Q starting(Rectangle2DDirection newDirection) {
		return create(r1, r2, newDirection);
	}
}
