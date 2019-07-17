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
package ghidra.app.merge.tool;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.merge.listing.CodeUnitDetails;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.fieldpanel.FieldPanel;

public class ViewInstructionDetailsAction extends ListingContextAction {

	private ListingMergePanelPlugin listingMergePanelPlugin;
	private static HelpLocation HELP_LOCATION = new HelpLocation("Repository", "CodeUnitsConflict");

	public ViewInstructionDetailsAction(ListingMergePanelPlugin listingMergePanelPlugin) {
		super("View Instruction Details", listingMergePanelPlugin.getName());
		this.listingMergePanelPlugin = listingMergePanelPlugin;
		setPopupMenuData(new MenuData(new String[] { "View Instruction Details..." }, null,
			"ViewInstructionDetails"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK |
			InputEvent.SHIFT_DOWN_MASK));
		setEnabled(true);
		setDescription("Display a dialog indicating details, such as references, for the "
			+ "instruction at the current cursor location.");
		setHelpLocation(HELP_LOCATION);
	}

	@Override
	protected boolean isValidContext(ListingActionContext context) {
		return (context.getSourceObject() instanceof FieldPanel);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		return (context.getCodeUnit() instanceof Instruction);
	}

	@Override
	protected boolean isAddToPopup(ListingActionContext context) {
		return isValidContext(context);
	}

	@Override
	protected void actionPerformed(ListingActionContext context) {
		// The location indicates the program for the current listing.
		ProgramLocation location = context.getLocation();
		Program program = location.getProgram();
		ListingMergePanel listingMergePanel =
			(ListingMergePanel) listingMergePanelPlugin.getProvider().getComponent();
		String version = listingMergePanel.getVersionName(program);
		Address address = location.getAddress();
		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		String detailString = CodeUnitDetails.getInstructionDetails(cu);
		String title = version + " version's Instruction Details @ " + address.toString();
		Dialog dialog = new Dialog(title, createDetailsPane(detailString));

		dialog.setHelpLocation(HELP_LOCATION);

		listingMergePanelPlugin.getTool().showDialog(dialog, listingMergePanel);
	}

	private JScrollPane createDetailsPane(String details) {
		Font font = new Font("Monospaced", Font.PLAIN, 12);

		JTextArea textArea = new JTextArea();
		textArea.setLineWrap(false);
		textArea.setEditable(false);
		textArea.setMargin(new Insets(5, 5, 5, 5));
		textArea.setFont(font);
		textArea.setOpaque(true);
		textArea.setCaretPosition(0);
		textArea.setText(details);
		textArea.setPreferredSize(new Dimension(700, 200));
		JScrollPane scrolledDetails = new JScrollPane(textArea);
		JViewport vp = scrolledDetails.getViewport();
		vp.add(textArea);

		scrolledDetails.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrolledDetails.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
		return scrolledDetails;
	}

	private static class Dialog extends DialogComponentProvider {
		Dialog(String title, JComponent workPanel) {
			super(title, true, false, true, false);
			init(workPanel);
		}

		private void init(JComponent workPanel) {
			addWorkPanel(workPanel);
			addOKButton();
			setRememberSize(true);
		}

		@Override
		protected void okCallback() {
			close();
		}
	}
}
