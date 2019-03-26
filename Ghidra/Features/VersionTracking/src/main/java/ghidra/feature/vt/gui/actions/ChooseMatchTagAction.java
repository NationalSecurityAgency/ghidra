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
package ghidra.feature.vt.gui.actions;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.*;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.editors.MatchTagComboBox;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchContext;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class ChooseMatchTagAction extends DockingAction {

	private static final String MENU_GROUP = VTPlugin.TAG_MENU_GROUP;
	private static final Icon EDIT_TAG_ICON = ResourceManager.loadImage("images/tag_blue.png");
	private static final String ACTION_NAME = "Choose Match Tag";

	private final VTController controller;
	private VTMatchTag lastTag;

	public ChooseMatchTagAction(VTController controller) {
		super(ACTION_NAME, VTPlugin.OWNER);
		this.controller = controller;
		setDescription("Choose Match Tag");
		setToolBarData(new ToolBarData(EDIT_TAG_ICON, MENU_GROUP));
		MenuData menuData = new MenuData(new String[] { "Choose Tag" }, EDIT_TAG_ICON, MENU_GROUP);
		menuData.setMenuSubGroup("1"); // 1st in the list
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Choose_Tag"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();
		if (matches.size() == 0) {
			return;
		}
		JComponent component = context.getComponentProvider().getComponent();
		editTag(matches, component);
	}

	private void editTag(final List<VTMatch> matches, final JComponent component) {

		if (matches == null || matches.size() == 0) {
			return;
		}
		VTSession session = controller.getSession();
		if (session == null) {
			return;
		}
		final TagChooserDialog dialog = new TagChooserDialog(session, matches, component, lastTag);
		dialog.setRememberSize(false);
		SwingUtilities.invokeLater(() -> {
			controller.getTool().showDialog(dialog, component);
			lastTag = dialog.getSelectedTag();
		});
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof VTMatchContext)) {
			return false;
		}
		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();
		if (matches.size() == 0) {
			return false;
		}
		return true;
	}

//==================================================================================================
// Inner Classes    
//==================================================================================================

	private class TagChooserDialog extends DialogComponentProvider {

		private JPanel editorPanel;
		private MatchTagComboBox tagComboBox;
		private final VTSession session;
		private final List<VTMatch> matches;
		private final JComponent component;

		private VTMatchTag selectedTag;

		protected TagChooserDialog(final VTSession session, final List<VTMatch> matches,
				final JComponent component, VTMatchTag selectedTag) {
			super("Choose Match Tag", true, true, true, false);
			this.session = session;
			this.matches = matches;
			this.component = component;
			this.selectedTag = selectedTag;
			editorPanel = createEditorPanel();
			addWorkPanel(editorPanel);
			addOKButton();
			addCancelButton();
			setDefaultButton(okButton);
		}

		private JPanel createEditorPanel() {
			JPanel panel = new JPanel(new BorderLayout());
			tagComboBox = new MatchTagComboBox(session, matches, component, selectedTag);
			Dimension dim = new Dimension(50, tagComboBox.getPreferredSize().height);
			tagComboBox.setMinimumSize(dim);
			tagComboBox.addActionListener(e -> fieldEdited());
			panel.add(tagComboBox, BorderLayout.CENTER);
			return panel;
		}

		@Override
		protected void cancelCallback() {
			super.cancelCallback();
		}

		@Override
		protected void okCallback() {
			selectedTag = (VTMatchTag) tagComboBox.getSelectedItem();

			tagComboBox.apply();
			close();
		}

		VTMatchTag getSelectedTag() {
			return selectedTag;
		}

		/**
		 * An address edit action occurred in the panel so handle it as if ok button were pressed.
		 */
		public void fieldEdited() {
			okCallback();
		}
	}
}
