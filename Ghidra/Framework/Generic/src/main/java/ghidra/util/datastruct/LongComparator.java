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
 * Interface that defines a method for comparing two long values.
 */
public interface LongComparator {
	
	/**
	 * Compares the long values a and b.
	 * @param a the first value
	 * @param b the second value
	 * @return 0 if a equals b; a number greater than 0 if a is greater than b;
	 * a number less than 0 if a is less than b.
	 */
	int compare(long a, long b);

}
