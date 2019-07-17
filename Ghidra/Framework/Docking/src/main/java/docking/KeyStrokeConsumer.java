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
package docking;

import javax.swing.KeyStroke;

/**
 * KeyActionConsumer identifies a Component which may want to limit the
 * use of actions associated with a KeyStroke when that Component has focus.
 */
public interface KeyStrokeConsumer {

	/**
	 * Returns true when the specified key stroke will be consumed
	 * and should not invoke an action.
	 * @param keyStroke key stroke
	 */
	boolean isKeyConsumed(KeyStroke keyStroke);
	
}
