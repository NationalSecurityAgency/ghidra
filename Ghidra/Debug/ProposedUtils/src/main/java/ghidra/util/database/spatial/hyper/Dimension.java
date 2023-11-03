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

public interface Dimension<T, P extends HyperPoint, B extends HyperBox<P, B>> {
	T value(P point);

	default T lower(B box) {
		return value(box.lCorner());
	}

	default T upper(B box) {
		return value(box.uCorner());
	}

	int compare(T a, T b);

	double distance(T a, T b);

	T mid(T a, T b);

	default T boxMid(B box) {
		return mid(lower(box), upper(box));
	}

	default T min(T a, T b) {
		return compare(a, b) < 0 ? a : b;
	}

	default T max(T a, T b) {
		return compare(a, b) > 0 ? a : b;
	}

	T absoluteMin();

	T absoluteMax();

	default double pointDistance(P a, P b) {
		return distance(value(a), value(b));
	}

	default boolean contains(B box, P point) {
		T value = value(point);
		if (compare(value, lower(box)) < 0) {
			return false;
		}
		if (compare(value, upper(box)) > 0) {
			return false;
		}
		return true;
	}

	default boolean intersect(B a, B b) {
		if (compare(lower(a), upper(b)) > 0) {
			return false;
		}
		if (compare(upper(a), lower(b)) < 0) {
			return false;
		}
		return true;
	}

	default boolean encloses(B outer, B inner) {
		if (compare(lower(outer), lower(inner)) > 0) {
			return false;
		}
		if (compare(upper(outer), upper(inner)) < 0) {
			return false;
		}
		return true;
	}

	default T intersectionLower(B a, B b) {
		return max(lower(a), lower(b));
	}

	default T intersectionUpper(B a, B b) {
		return min(upper(a), upper(b));
	}

	default T unionLower(B a, B b) {
		return min(lower(a), lower(b));
	}

	default T unionUpper(B a, B b) {
		return max(upper(a), upper(b));
	}

	default double measure(B box) {
		return distance(upper(box), lower(box));
	}
}
