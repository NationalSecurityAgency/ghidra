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
package ghidra.util.graph;

import java.util.Vector;

public class Path extends Vector {

	public boolean containsInSomeElement(Vector otherVector) {
		for (int i = 0; i < size(); i++) {
			Vector path = (Vector) elementAt(i);
			if (path.size() >= otherVector.size()) {
				if (hasSameChildren(path, otherVector)) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean hasSameChildren(Vector v1, Vector v2) {
		for (int j = 0; j < v2.size(); j++) {
			if (v1.elementAt(j) != v2.elementAt(j)) {
				return false;
			}
		}
		return true;
	}
}
