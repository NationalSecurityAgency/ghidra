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
import ghidra.util.exception.AssertException;

public class AddBitFieldAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Add Bitfield";
	private final static String GROUP_NAME = BITFIELD_ACTION_GROUP;
	private final static String DESCRIPTION =
		"Add a bitfield at the position of a selected component";
	private static String[] POPUP_PATH = new String[] { ACTION_NAME };

	public AddBitFieldAction(CompositeEditorProvider<?, ?> provider) {
		super(provider, ACTION_NAME, GROUP_NAME, POPUP_PATH, null, null);
		setDescription(DESCRIPTION);
		if (!(model instanceof CompEditorModel)) {
			throw new AssertException("unsupported use");
		}
	}

	@Override
	public void actionPerformed(ActionContext context) {
		StructureEditorProvider structProvider = (StructureEditorProvider) provider;
		structProvider.showAddBitFieldEditor();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (hasIncompleteFieldEntry()) {
			return false;
		}
		boolean enabled = true;
		CompEditorModel<?> editorModel = (CompEditorModel<?>) model;
		// Unions do not support non-packed manipulation of bitfields
		if (!(provider instanceof StructureEditorProvider) ||
			editorModel.isPackingEnabled() || editorModel.getNumSelectedRows() != 1) {
			enabled = false;
		}
		return enabled;
	}

}
