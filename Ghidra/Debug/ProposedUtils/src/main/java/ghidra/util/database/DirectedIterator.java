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
package ghidra.util.database;

import java.io.IOException;

import db.Table;
import generic.End.Point;

/**
 * An iterator over some component of a {@link Table}
 * 
 * @param <T> the type of the component, i.e., a key or record
 */
public interface DirectedIterator<T> {
	/**
	 * The direction of iteration
	 */
	public enum Direction {
		FORWARD {
			@Override
			Direction reverse() {
				return BACKWARD;
			}
		},
		BACKWARD {
			@Override
			Direction reverse() {
				return FORWARD;
			}
		};

		/**
		 * Get the reverse of this direction
		 * 
		 * @return the reverse
		 */
		abstract Direction reverse();

		/**
		 * Get the reverse of the given direction
		 * 
		 * @param direction the direction
		 * @return the reverse
		 */
		static Direction reverse(Direction direction) {
			return direction.reverse();
		}
	}

	/**
	 * Check if the table has another record
	 * 
	 * @return true if so
	 * @throws IOException if the table cannot be read
	 */
	boolean hasNext() throws IOException;

	/**
	 * Get the component of the next record
	 * 
	 * @return the component
	 * @throws IOException if the table cannot be read
	 */
	T next() throws IOException;

	/**
	 * Delete the current record
	 * 
	 * @return true if successful
	 * @throws IOException if the table cannot be accessed
	 */
	boolean delete() throws IOException;
}
