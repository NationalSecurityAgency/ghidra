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
package ghidra.util.bytesearch;

/**
 * Template for generic match action attached to a match sequence.
 * Used to store an associated value to the matching sequence.
 * The associated value can be retrieved when the sequence is matched.
 *
 * @param <T> - object to attach to match sequence, generally used to specify
 * a specialized momento to be used by the action when it is "applied".
 */
public class GenericMatchAction<T> extends DummyMatchAction {
	T matchValue;

	/**
	 * Construct a match action used when a match occurs for some GenericByteSequece
	 * @param matchValue specialized object used when match occurs
	 */
	public GenericMatchAction(T matchValue) {
		this.matchValue = matchValue;
	}

	/**
	 * @return the specialized object associated with this match action
	 */
	public T getMatchValue() {
		return this.matchValue;
	}
}
