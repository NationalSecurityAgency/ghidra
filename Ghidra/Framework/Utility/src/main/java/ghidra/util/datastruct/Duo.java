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
package ghidra.util.datastruct;

import static ghidra.util.datastruct.Duo.Side.*;

import java.util.Objects;
import java.util.function.Consumer;

/**
 * Class for holding two objects of the same type. We are using the idiom of LEFT and RIGHT to 
 * refer to each item in this pair of objects.
 * The enum "Side" is used to represent either the LEFT (or first) or RIGHT (or second) item.
 *
 * @param <T> The type of item that is stored in this Duo.
 */
public class Duo<T> {
	public enum Side {
		LEFT, RIGHT;

		public Side otherSide() {
			return this == LEFT ? RIGHT : LEFT;
		}
	}

	private final T left;
	private final T right;

	/**
	 * Constructor with no values.
	 */
	public Duo() {
		this(null, null);
	}

	/**
	 * Constructor with a left and right value.
	 * @param left the left value
	 * @param right the right value
	 */
	public Duo(T left, T right) {
		this.left = left;
		this.right = right;
	}

	/**
	 * Gets the value for the given side.
	 * @param side LEFT or RIGHT
	 * @return the value for the given side
	 */
	public T get(Side side) {
		return side == LEFT ? left : right;
	}

	/**
	 * Creates a new Duo, replacing the value for just one side. The other side uses the value 
	 * from this Duo.
	 * @param side the side that gets a new value
	 * @param newValue the new value for the given side
	 * @return the new Duo
	 * value as this
	 */
	public Duo<T> with(Side side, T newValue) {
		if (side == LEFT) {
			return new Duo<>(newValue, right);
		}
		return new Duo<>(left, newValue);
	}

	/**
	 * Invokes the given consumer on both the left and right values.
	 * @param c the consumer to invoke on both values
	 */
	public void each(Consumer<T> c) {
		if (left != null) {
			c.accept(left);
		}
		if (right != null) {
			c.accept(right);
		}
	}

	/**
	 * Returns true if both values are equals to this objects values.
	 * @param otherLeft the value to compare to our left side value
	 * @param otherRight the value to compare to our right side value
	 * @return true if both values are equals to this objects values
	 */
	public boolean equals(T otherLeft, T otherRight) {
		return Objects.equals(left, otherLeft) && Objects.equals(right, otherRight);
	}

	@Override
	public int hashCode() {
		return Objects.hash(left, right);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Duo<?> other = (Duo<?>) obj;
		return Objects.equals(left, other.left) && Objects.equals(right, other.right);
	}

}
