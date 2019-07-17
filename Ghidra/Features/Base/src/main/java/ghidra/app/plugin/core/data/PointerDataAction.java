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
package ghidra.app.plugin.core.data;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

public class PointerDataAction extends DataAction {

	private final static KeyStroke POINTER_KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_P, 0);

	public PointerDataAction(DataPlugin plugin) {
		super(DataPlugin.POINTER_DATA_TYPE, plugin);
	}

	@Override
	protected KeyStroke getDefaultKeyStroke() {
		return POINTER_KEY_BINDING;
	}
}
