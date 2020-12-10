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

public interface Point2D<X, Y> {
	X getX();

	Y getY();

	EuclideanSpace2D<X, Y> getSpace();

	default double computeDistance(Point2D<X, Y> point) {
		double distX = getSpace().distX(getX(), point.getX());
		double distY = getSpace().distY(getY(), point.getY());
		return distX * distX + distY * distY;
	}
}
