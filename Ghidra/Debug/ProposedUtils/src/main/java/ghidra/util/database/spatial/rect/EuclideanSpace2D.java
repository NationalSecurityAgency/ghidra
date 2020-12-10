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

public interface EuclideanSpace2D<X, Y> {
	int compareX(X x1, X x2);

	int compareY(Y y1, Y y2);

	double distX(X x1, X x2);

	double distY(Y y1, Y y2);

	X midX(X x1, X x2);

	Y midY(Y y1, Y y2);

	default X minX(X x1, X x2) {
		return compareX(x1, x2) < 0 ? x1 : x2;
	}

	default X maxX(X x1, X x2) {
		return compareX(x1, x2) > 0 ? x1 : x2;
	}

	default Y minY(Y y1, Y y2) {
		return compareY(y1, y2) < 0 ? y1 : y2;
	}

	default Y maxY(Y y1, Y y2) {
		return compareY(y1, y2) > 0 ? y1 : y2;
	}

	Rectangle2D<X, Y, ?> getFull();
}
