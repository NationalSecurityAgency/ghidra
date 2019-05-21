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

import java.awt.BorderLayout;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GIconLabel;
import docking.widgets.label.GLabel;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * Dialog that confirms undo of an action; specify whether a .keep file
 * should be created on the undo of the action.
 * 
 */
public class UndoActionDialog extends DialogComponentProvider {
	static final int OK = 0;
	public static final int CANCEL = 1;

	private List<DomainFile> fileList;
	private DomainFilesPanel filePanel;
	private JCheckBox saveCopyCB;
	private int actionID;

	/**
	 * Constructor
	 * @param fileList list of DomainFile objects to show in the list
	 */
	public UndoActionDialog(String title, ImageIcon icon, String helpTag, String actionString,
			List<DomainFile> fileList) {
		super(title, true);
		setHelpLocation(new HelpLocation(GenericHelpTopics.REPOSITORY, helpTag));
		this.fileList = fileList;
		addWorkPanel(buildMainPanel(actionString, icon));

		addOKButton();
		addCancelButton();
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.GhidraDialog#cancelCallback()
	 */
	@Override
	protected void cancelCallback() {
		actionID = CANCEL;
		close();
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.GhidraDialog#okCallback()
	 */
	@Override
	protected void okCallback() {
		actionID = OK;
		close();
	}

	/**
	 * Show the dialog; return an ID for the action that the user chose.
	 * @return OK, or CANCEL
	 */
	public int showDialog(PluginTool tool) {
		tool.showDialog(this);
		return actionID;
	}

	public DomainFile[] getSelectedDomainFiles() {
		return filePanel.getSelectedDomainFiles();
	}

	public boolean saveCopy() {
		return saveCopyCB.isSelected();
	}

	private JPanel buildMainPanel(String actionString, ImageIcon icon) {
		JPanel innerPanel = new JPanel();
		innerPanel.setLayout(new BoxLayout(innerPanel, BoxLayout.Y_AXIS));
		innerPanel.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));

		filePanel = new DomainFilesPanel(fileList, null);
		saveCopyCB = new GCheckBox("Save copy of the file with a .keep extension", true);
		JPanel cbPanel = new JPanel(new BorderLayout());
		cbPanel.add(saveCopyCB);

		JPanel iconPanel = new JPanel(new BorderLayout(10, 0));
		iconPanel.add(new GIconLabel(icon), BorderLayout.WEST);
		iconPanel.add(
			new GLabel("Undo " + actionString + " of the selected files:", SwingConstants.LEFT),
			BorderLayout.CENTER);

		innerPanel.add(Box.createVerticalStrut(10));
		innerPanel.add(iconPanel);
		innerPanel.add(Box.createVerticalStrut(5));
		innerPanel.add(filePanel);
		innerPanel.add(Box.createVerticalStrut(10));
		innerPanel.add(cbPanel);

		return innerPanel;
	}
}
