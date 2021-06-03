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

import java.util.NoSuchElementException;
import java.util.Objects;

import ghidra.util.database.spatial.BoundingShape;

public interface Rectangle2D<X, Y, R extends Rectangle2D<X, Y, R>> extends BoundingShape<R> {
	static <X, Y> boolean encloses(Rectangle2D<X, Y, ?> outer, Rectangle2D<X, Y, ?> inner) {
		if (outer.getSpace().compareX(outer.getX1(), inner.getX1()) > 0) {
			return false;
		}
		if (outer.getSpace().compareX(outer.getX2(), inner.getX2()) < 0) {
			return false;
		}
		if (outer.getSpace().compareY(outer.getY1(), inner.getY1()) > 0) {
			return false;
		}
		if (outer.getSpace().compareY(outer.getY2(), inner.getY2()) < 0) {
			return false;
		}
		return true;
	}

	X getX1();

	X getX2();

	Y getY1();

	Y getY2();

	EuclideanSpace2D<X, Y> getSpace();

	// Assume sub-equality check will check types
	@SuppressWarnings("rawtypes")
	default boolean doEquals(Object obj) {
		if (!(obj instanceof Rectangle2D)) {
			return false;
		}
		Rectangle2D that = (Rectangle2D) obj;
		if (!this.getX1().equals(that.getX1())) {
			return false;
		}
		if (!this.getX2().equals(that.getX2())) {
			return false;
		}
		if (!this.getY1().equals(that.getY1())) {
			return false;
		}
		if (!this.getY2().equals(that.getY2())) {
			return false;
		}
		return true;
	}

	default int doHashCode() {
		return Objects.hash(getX1(), getX2(), getY1(), getY2());
	}

	default boolean contains(Point2D<X, Y> point) {
		return contains(point.getX(), point.getY());
	}

	default boolean contains(X x, Y y) {
		if (getSpace().compareX(x, getX1()) < 0) {
			return false;
		}
		if (getSpace().compareX(x, getX2()) > 0) {
			return false;
		}
		if (getSpace().compareY(y, getY1()) < 0) {
			return false;
		}
		if (getSpace().compareY(y, getY2()) > 0) {
			return false;
		}
		return true;
	}

	@Override
	default double getArea() {
		double width = getSpace().distX(getX2(), getX1()) + 1;
		double height = getSpace().distY(getY2(), getY1()) + 1;
		return width * height;
	}

	@Override
	default double getMargin() {
		double width = getSpace().distX(getX2(), getX1()) + 1;
		double height = getSpace().distY(getY2(), getY1()) + 1;
		return width + height;
	}

	default Point2D<X, Y> getCenter() {
		return new ImmutablePoint2D<>(getSpace().midX(getX1(), getX2()),
			getSpace().midY(getY1(), getY2()), getSpace());
	}

	@Override
	default double computeAreaUnionBounds(R shape) {
		X unionX1 = getSpace().minX(this.getX1(), shape.getX1());
		X unionX2 = getSpace().maxX(this.getX2(), shape.getX2());
		Y unionY1 = getSpace().minY(this.getY1(), shape.getY1());
		Y unionY2 = getSpace().maxY(this.getY2(), shape.getY2());
		double width = getSpace().distX(unionX2, unionX1) + 1;
		double height = getSpace().distY(unionY2, unionY1) + 1;
		return width * height;
	}

	@Override
	default double computeAreaIntersection(R shape) {
		X intX1 = getSpace().maxX(this.getX1(), shape.getX1());
		X intX2 = getSpace().minX(this.getX2(), shape.getX2());
		Y intY1 = getSpace().maxY(this.getY1(), shape.getY1());
		Y intY2 = getSpace().minY(this.getY2(), shape.getY2());
		if (getSpace().compareX(intX1, intX2) > 0 || getSpace().compareY(intY1, intY2) > 0) {
			return 0;
		}
		double width = getSpace().distX(intX2, intX1) + 1;
		double height = getSpace().distY(intY2, intY1) + 1;
		return width * height;
	}

	@Override
	default double computeCentroidDistance(R shape) {
		return getCenter().computeDistance(shape.getCenter());
	}

	R immutable(X x1, X x2, Y y1, Y y2);

	@Override
	default R unionBounds(R shape) {
		X unionX1 = getSpace().minX(this.getX1(), shape.getX1());
		X unionX2 = getSpace().maxX(this.getX2(), shape.getX2());
		Y unionY1 = getSpace().minY(this.getY1(), shape.getY1());
		Y unionY2 = getSpace().maxY(this.getY2(), shape.getY2());
		return immutable(unionX1, unionX2, unionY1, unionY2);
	}

	default boolean intersects(R shape) {
		if (getSpace().compareX(this.getX1(), shape.getX2()) > 0) {
			return false;
		}
		if (getSpace().compareX(this.getX2(), shape.getX1()) < 0) {
			return false;
		}
		if (getSpace().compareY(this.getY1(), shape.getY2()) > 0) {
			return false;
		}
		if (getSpace().compareY(this.getY2(), shape.getY1()) < 0) {
			return false;
		}
		return true;
	}

	default R intersection(R shape) {
		X intX1 = getSpace().maxX(this.getX1(), shape.getX1());
		X intX2 = getSpace().minX(this.getX2(), shape.getX2());
		Y intY1 = getSpace().maxY(this.getY1(), shape.getY1());
		Y intY2 = getSpace().minY(this.getY2(), shape.getY2());
		if (getSpace().compareX(intX1, intX2) > 0 || getSpace().compareY(intY1, intY2) > 0) {
			throw new NoSuchElementException();
		}
		return immutable(intX1, intX2, intY1, intY2);
	}

	/**
	 * Check if this rectangle encloses another rectangle
	 * 
	 * @param shape the other (presumably-inner) rectangle
	 * @return true if this rectangle encloses the other
	 */
	default boolean encloses(R shape) {
		return encloses(this, shape);
	}

	/**
	 * Check if this rectangle is enclosed by another rectangle
	 * 
	 * @param shape the other (presumably-outer) rectangle
	 * @return true if this rectangle is enclosed by the other
	 */
	default boolean enclosedBy(R shape) {
		return encloses(shape, this);
	}
}
