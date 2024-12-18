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
package ghidra.app.util.pdb.classtype;

/**
 * Unique ID of a ClassType.  Not sure if there will be different implementation for definition
 *  vs. compiled vs. program vs. debug.  Need to come to grips with this
 */
public interface ClassID extends Comparable<ClassID> {

	// For compareTo() method of classes in this hierarchy (for Comparable<ClassID>)
	/**
	 * For internal use
	 * @return hash of java class in ClassID hierarchy
	 */
	public int getClassNameHash();

}
