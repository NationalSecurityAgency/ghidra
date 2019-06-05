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

import javax.swing.JComponent;

import docking.DialogComponentProvider;
import ghidra.program.model.data.*;

public class BitFieldViewerDialog extends DialogComponentProvider {

	BitFieldViewerDialog(Composite composite, int editOrdinal) {
		super("View " + getCompositeType(composite) + " Bitfield");
		addButtons();
		addWorkPanel(buildWorkPanel(composite, editOrdinal));
		setRememberLocation(false);
		setRememberSize(false);
	}

	private void addButtons() {
		addCancelButton();
		setCancelButtonText("Close");
	}

	private JComponent buildWorkPanel(Composite composite, int viewOrdinal) {
		if (viewOrdinal < 0 || viewOrdinal >= composite.getNumComponents()) {
			throw new IllegalArgumentException("invalid composite ordinal");
		}
		DataTypeComponent dtc = composite.getComponent(viewOrdinal);
		if (!dtc.isBitFieldComponent()) {
			throw new IllegalArgumentException("editOrdinal does not correspond to bitfield");
		}
		return new BitFieldViewerPanel(dtc, BitFieldEditorDialog.getPreferredAllocationOffset(dtc));
	}

	private static String getCompositeType(Composite composite) {
		// currently supports unaligned case only!
		String alignmentMode = composite.isInternallyAligned() ? "Aligned" : "Unaligned";
		String type = (composite instanceof Union) ? "Union" : "Structure";
		return alignmentMode + " " + type;
	}

}
