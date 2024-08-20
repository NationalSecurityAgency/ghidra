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

public class EditBitFieldAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Edit Bitfield";
	private final static String GROUP_NAME = BITFIELD_ACTION_GROUP;
	private final static String DESCRIPTION = "Edit an existing bitfield";
	private static String[] POPUP_PATH = new String[] { ACTION_NAME };

	public EditBitFieldAction(CompositeEditorProvider provider) {
		super(provider, ACTION_NAME, GROUP_NAME, POPUP_PATH, null, null);
		setDescription(DESCRIPTION);
		if (!(model instanceof CompEditorModel)) {
			throw new AssertException("unsupported use");
		}
	}

	@Override
	public void actionPerformed(ActionContext context) {
		StructureEditorProvider structProvider = (StructureEditorProvider) provider;
		structProvider.showBitFieldEditor();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return !hasIncompleteFieldEntry() &&
			(provider instanceof StructureEditorProvider structProvider) &&
			structProvider.getSelectedNonPackedBitFieldComponent() != null;
	}
}
