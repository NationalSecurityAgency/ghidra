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

import com.google.common.collect.Range;

import db.Table;

public interface DirectedLongKeyIterator extends DirectedIterator<Long> {
	public static AbstractDirectedLongKeyIterator getIterator(Table table, Range<Long> keyRange,
			Direction direction) throws IOException {
		long min = DirectedIterator.toIteratorMin(keyRange);
		long max = DirectedIterator.toIteratorMax(keyRange);
		if (direction == Direction.FORWARD) {
			return new ForwardLongKeyIterator(table.longKeyIterator(min, max, min));
		}
		return new BackwardLongKeyIterator(table.longKeyIterator(min, max, max));
	}
}
