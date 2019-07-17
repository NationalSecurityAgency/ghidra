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
package ghidra.util.datastruct;

/**
 * Iterator over a set of Java-type int values.
 * 
 */
public interface IntIterator {
	/**
	 * Return true if there is a next int in this iterator.
	 */
    public boolean hasNext();
    
	/**
	 * Get the next int value in this iterator.
	 */
    public int next();
    
    /**
     * Return true if there a previous int in this iterator.
     */
    public boolean hasPrevious();
	/**
	 * Get the previous int value in this iterator.
	 */
    public int previous();
     
    /**
     * Removes from the underlying collection the last element returned 
     * by the iterator (optional operation). 
     *
     */
    public void remove();
}
