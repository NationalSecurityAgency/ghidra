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

import docking.ActionContext;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.UsrException;

/**
 * Action to apply a favorite data type.
 * Used in a composite data type editor.
 * This action has help associated with it.
 */
public class FavoritesAction extends CompositeEditorTableAction {

	private final static String GROUP_NAME = DATA_ACTION_GROUP;
	private DataType dataType;

	/**
	 * Creates an action for applying a favorite data type.
	 * @param provider the provider that owns this action
	 * @param dt the favorite data type
	 */
	public FavoritesAction(CompositeEditorProvider provider, DataType dt) {
		super(provider, dt.getDisplayName(), GROUP_NAME,
			new String[] { "Favorite", dt.getDisplayName() },
			new String[] { "Favorite", dt.getDisplayName() }, null);
		this.dataType = dt;
		getPopupMenuData().setParentMenuGroup(GROUP_NAME);
		adjustEnablement();
	}

	public DataType getDataType() {
		return dataType;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		try {
			model.add(dataType);
		}
		catch (UsrException e1) {
			model.setStatus(e1.getMessage());
		}
		requestTableFocus();
	}

	@Override
	public void adjustEnablement() {
		// we always want it enabled so the user gets a "doesn't fit" message.
		setEnabled(true);
	}

	@Override
	public String getHelpName() {
		return "Favorite";
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return model.isAddAllowed(dataType);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return isEnabledForContext(context);
	}
}
