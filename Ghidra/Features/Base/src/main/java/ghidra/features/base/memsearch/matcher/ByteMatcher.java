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
package ghidra.features.base.memsearch.matcher;

import ghidra.util.bytesearch.ExtendedByteSequence;
import ghidra.util.bytesearch.Match;

/**
 * ByteMatcher is the base class for an object that be used to scan bytes looking for sequences
 * that match some criteria. As a convenience, it also stores the input string and settings that
 * were used to generated this ByteMatcher.
 * @param <T> The type of object used by the client to identify the matched pattern
 */
public interface ByteMatcher<T> {

	public Iterable<Match<T>> match(ExtendedByteSequence bytes);

	public String getDescription();

}
