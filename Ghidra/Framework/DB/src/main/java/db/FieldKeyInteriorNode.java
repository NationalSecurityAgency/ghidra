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
package db;

import java.io.IOException;

/**
 * <code>FieldKeyInteriorNode</code> defines a common interface for {@link FieldKeyNode} 
 * implementations which are also an {@link InteriorNode}.
 */
public interface FieldKeyInteriorNode extends InteriorNode, FieldKeyNode {

	/**
	 * Callback method for when a child node's leftmost key changes.
	 * @param oldKey previous leftmost key.
	 * @param newKey new leftmost key.
	 * @param childNode child node containing oldKey (null if not a VarKeyNode)
	 * @throws IOException if IO error occurs
	 */
	void keyChanged(Field oldKey, Field newKey, FieldKeyNode childNode) throws IOException;

}
