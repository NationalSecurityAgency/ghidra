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
package ghidra.framework.main.datatree;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import ghidra.framework.main.datatable.ProjectTreeAction;

public class ClearCutAction extends ProjectTreeAction {

	public ClearCutAction(String owner) {
		super("Clear Cut", owner);
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_ESCAPE, 0));
		setEnabled(true);
		markHelpUnnecessary();
	}

	@Override
	public boolean isEnabledForContext(FrontEndProjectTreeContext context) {
		return DataTreeClipboardUtils.isCuttablePresent();
	}

	@Override
	public void actionPerformed(FrontEndProjectTreeContext context) {
		DataTreeClipboardUtils.clearCuttables();
	}
}
