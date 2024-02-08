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

import java.util.List;
import java.util.Objects;

public interface EuclideanHyperSpace<P extends HyperPoint, B extends HyperBox<P, B>> {
	List<Dimension<?, P, B>> getDimensions();

	B getFull();

	default boolean boxesEqual(B a, B b) {
		for (Dimension<?, P, B> dim : getDimensions()) {
			if (!Objects.equals(dim.lower(a), dim.lower(b))) {
				return false;
			}
			if (!Objects.equals(dim.upper(a), dim.upper(b))) {
				return false;
			}
		}
		return true;
	}

	default Object[] collectBounds(B box) {
		List<Dimension<?, P, B>> dims = getDimensions();
		Object[] result = new Object[dims.size() * 2];
		for (int i = 0; i < dims.size(); i++) {
			Dimension<?, P, B> d = dims.get(i);
			result[i * 2] = d.lower(box);
			result[i * 2 + 1] = d.upper(box);
		}
		return result;
	}

	default boolean boxContains(B box, P point) {
		for (Dimension<?, P, B> dim : getDimensions()) {
			if (!dim.contains(box, point)) {
				return false;
			}
		}
		return true;
	}

	default double boxArea(B box) {
		double result = 1;
		for (Dimension<?, P, B> dim : getDimensions()) {
			result *= 1 + dim.measure(box);
		}
		return result;
	}

	default double boxMargin(B box) {
		double result = 0;
		for (Dimension<?, P, B> dim : getDimensions()) {
			result += 1 + dim.measure(box);
		}
		return result;
	}

	P boxCenter(B box);

	default <T> double measureUnion(Dimension<T, P, B> dim, B a, B b) {
		T unionLower = dim.unionLower(a, b);
		T unionUpper = dim.unionUpper(a, b);
		return dim.distance(unionUpper, unionLower);
	}

	default double computeAreaUnionBounds(B a, B b) {
		double result = 1;
		for (Dimension<?, P, B> dim : getDimensions()) {
			result *= 1 + measureUnion(dim, a, b);
		}
		return result;
	}

	default <T> double measureIntersection(Dimension<T, P, B> dim, B a, B b) {
		T intLower = dim.intersectionLower(a, b);
		T intUpper = dim.intersectionUpper(a, b);
		if (dim.compare(intLower, intUpper) > 0) {
			return 0;
		}
		return dim.distance(intUpper, intLower);
	}

	default double computeAreaIntersection(B a, B b) {
		double result = 1;
		for (Dimension<?, P, B> dim : getDimensions()) {
			double measure = measureIntersection(dim, a, b);
			if (measure == 0) {
				return 0;
			}
			result *= 1 + measure;
		}
		return result;
	}

	default double sqDistance(P a, P b) {
		double result = 0;
		for (Dimension<?, P, B> dim : getDimensions()) {
			double dist = dim.pointDistance(a, b);
			result += dist * dist;
		}
		return result;
	}

	B boxUnionBounds(B a, B b);

	B boxIntersection(B b, B shape);

	default boolean boxEncloses(B outer, B inner) {
		for (Dimension<?, P, B> dim : getDimensions()) {
			if (!dim.encloses(outer, inner)) {
				return false;
			}
		}
		return true;
	}
}
