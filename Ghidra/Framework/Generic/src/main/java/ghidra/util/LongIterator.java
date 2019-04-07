/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util;

/**
 * Iterator over a set of Java-type long values.
 * 
 */
public interface LongIterator { 
	/**
	 * A default implementation of LongIterator that has no values.
	 */
	public final static LongIterator EMPTY = new LongIterator() {
		public boolean hasNext() {
			return false;
		}
		public long next() {
			return 0;
		}
		public boolean hasPrevious() {
			return false;
		}
		public long previous() {
			return 0;
		}
	};

	/**
	 * Return true if there is a next long in this iterator.
	 */
    public boolean hasNext();
	/**
	 * Get the next long value in this iterator.
	 */
    public long next();
    
    /**
     * Return true if there a previous long in this iterator.
     */
    public boolean hasPrevious();
	/**
	 * Get the previous long value in this iterator.
	 */
    public long previous();
}
