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

public abstract class ImmutableRectangle2D<X, Y, R extends Rectangle2D<X, Y, R>>
		implements Rectangle2D<X, Y, R> {
	protected final X x1;
	protected final X x2;
	protected final Y y1;
	protected final Y y2;
	protected final EuclideanSpace2D<X, Y> space;

	public ImmutableRectangle2D(X x1, X x2, Y y1, Y y2, EuclideanSpace2D<X, Y> space) {
		assert space.compareX(x1, x2) <= 0;
		assert space.compareY(y1, y2) <= 0;
		this.x1 = x1;
		this.x2 = x2;
		this.y1 = y1;
		this.y2 = y2;
		this.space = space;
	}

	@Override
	public String toString() {
		return String.format("rect[%s-%s]x[%s-%s]", x1, x2, y1, y2);
	}

	@Override
	public String description() {
		return toString();
	}

	@Override
	public X getX1() {
		return x1;
	}

	@Override
	public X getX2() {
		return x2;
	}

	@Override
	public Y getY1() {
		return y1;
	}

	@Override
	public Y getY2() {
		return y2;
	}

	@Override
	public EuclideanSpace2D<X, Y> getSpace() {
		return space;
	}

	@Override
	public boolean equals(Object obj) {
		return doEquals(obj);
	}

	@Override
	public int hashCode() {
		return doHashCode();
	}
}
