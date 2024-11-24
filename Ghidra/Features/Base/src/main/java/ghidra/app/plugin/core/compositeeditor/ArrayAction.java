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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.event.KeyEvent;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;
import generic.theme.GIcon;
import ghidra.util.exception.UsrException;

/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class ArrayAction extends CompositeEditorTableAction {

	private final static Icon ICON = new GIcon("icon.plugin.composite.editor.array");
	public final static String ACTION_NAME = "Create Array";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static String DESCRIPTION = "Create an array";
	private final static KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_OPEN_BRACKET, 0);
	private static String[] POPUP_PATH = new String[] { ACTION_NAME };

	public ArrayAction(CompositeEditorProvider provider) {
		super(provider, ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);
		setDescription(DESCRIPTION);
		setKeyBindingData(new KeyBindingData(KEY_STROKE));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!isEnabledForContext(context)) {
			return;
		}
		try {
			model.createArray();
		}
		catch (UsrException e1) {
			model.setStatus(e1.getMessage());
		}
		requestTableFocus();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return !hasIncompleteFieldEntry() && model.isArrayAllowed();
	}

}
