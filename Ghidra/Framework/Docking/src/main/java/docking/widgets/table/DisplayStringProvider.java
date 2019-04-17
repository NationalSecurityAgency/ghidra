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
package docking.widgets.table;

/**
 * An interface used by classes to indicate that they can produce a String representation that
 * is meant to be seen by the user in the UI.  One example use of this interface is the 
 * table filtering mechanism, which will look for this interface when attempting to transform
 * table cell data to filterable Strings.
 */
public interface DisplayStringProvider {

	/**
	 * Returns a display String suitable for user consumption
	 * @return a display String suitable for user consumption
	 */
	public String getDisplayString();
}
