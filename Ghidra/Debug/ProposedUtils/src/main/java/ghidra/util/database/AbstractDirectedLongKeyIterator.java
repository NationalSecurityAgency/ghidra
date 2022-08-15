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

import db.DBLongIterator;

/**
 * An abstract implementation of {@link DirectedLongKeyIterator}
 * 
 * <p>
 * Essentially, this just wraps a {@link DBLongIterator}, but imposes and encapsulates its
 * direction.
 */
public abstract class AbstractDirectedLongKeyIterator implements DirectedLongKeyIterator {
	protected final DBLongIterator it;

	/**
	 * Wrap the given iterator
	 * 
	 * @param it the iterator
	 */
	public AbstractDirectedLongKeyIterator(DBLongIterator it) {
		this.it = it;
	}

	@Override
	public boolean delete() throws IOException {
		return it.delete();
	}
}
