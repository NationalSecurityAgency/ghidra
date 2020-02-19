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
 * Interface for factories that create Match Pattern classes
 */
public interface PatternFactory {
	/**
	 * Get a named match action
	 * 
	 * @param nm name of action to find
	 * @return match action with the given name, null otherwise
	 */
	public MatchAction getMatchActionByName(String nm);

	/**
	 * Get a named post match rule by name
	 * @param nm name of the post rule
	 * @return the post rule with the name, null otherwise
	 */
	public PostRule getPostRuleByName(String nm);
}
