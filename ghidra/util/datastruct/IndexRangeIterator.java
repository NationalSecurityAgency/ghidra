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
 * Iterator interface for index ranges.
 */
public interface IndexRangeIterator {
	
	/**
	 * Returns true if there are more index ranges.
	 * @return true if there are more index ranges.
	 */
	public boolean hasNext();
	
	/**
	 * Returns the next index range.
	 * @return the next index range.
	 */
	public IndexRange next();
	
}
