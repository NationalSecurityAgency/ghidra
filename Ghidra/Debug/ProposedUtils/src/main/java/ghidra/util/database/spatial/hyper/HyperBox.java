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

import java.util.Objects;

import ghidra.util.database.spatial.BoundingShape;

public interface HyperBox<P extends HyperPoint, B extends HyperBox<P, B>> extends BoundingShape<B> {
	EuclideanHyperSpace<P, B> space();

	@SuppressWarnings("unchecked")
	default boolean doEquals(Object obj) {
		if (!(obj instanceof HyperBox<?, ?> that)) {
			return false;
		}
		if (this.space() != that.space()) {
			return false;
		}
		return space().boxesEqual((B) this, (B) that);
	}

	@SuppressWarnings("unchecked")
	default int doHashCode() {
		return Objects.hash(space().collectBounds((B) this));
	}

	@SuppressWarnings("unchecked")
	default boolean contains(P p) {
		return space().boxContains((B) this, p);
	}

	@Override
	@SuppressWarnings("unchecked")
	default double getArea() {
		return space().boxArea((B) this);
	}

	@Override
	@SuppressWarnings("unchecked")
	default double getMargin() {
		return space().boxMargin((B) this);
	}

	@SuppressWarnings("unchecked")
	default P getCenter() {
		return space().boxCenter((B) this);
	}

	@Override
	@SuppressWarnings("unchecked")
	default double computeAreaUnionBounds(B shape) {
		return space().computeAreaUnionBounds((B) this, shape);
	}

	@Override
	@SuppressWarnings("unchecked")
	default double computeAreaIntersection(B shape) {
		return space().computeAreaIntersection((B) this, shape);
	}

	@Override
	default double computeCentroidDistance(B shape) {
		return space().sqDistance(this.getCenter(), shape.getCenter());
	}

	@Override
	@SuppressWarnings("unchecked")
	default B unionBounds(B shape) {
		return space().boxUnionBounds((B) this, shape);
	}

	@Override
	@SuppressWarnings("unchecked")
	default boolean encloses(B shape) {
		return space().boxEncloses((B) this, shape);
	}

	P lCorner();

	P uCorner();

	B immutable(P lCorner, P uCorner);

	@SuppressWarnings("unchecked")
	default B intersection(B shape) {
		return space().boxIntersection((B) this, shape);
	}
}
