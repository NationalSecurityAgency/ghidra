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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.*;

import docking.DialogComponentProvider;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Dialog to prompt user to save files before adding files to source control
 * or checking in files.
 */
public class ChangedFilesDialog extends DialogComponentProvider {

	private ArrayList<DomainFile> fileList;
    private DomainFilesPanel filePanel;
    private PluginTool tool;
    private boolean saveSelected;
 
	/** 
	 * Constructor 
	 * @param tool tool to execute task and log messages in status window
	 * @param list list of domain files that have changes
	 */
	public ChangedFilesDialog(PluginTool tool, ArrayList<DomainFile> list) { 
		super("Save Changed Files?", true);
		this.tool = tool;
		this.fileList = list;
		addWorkPanel(buildMainPanel());

		JButton saveButton = new JButton("Save");
		saveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				save();
			}
		});
		saveButton.setToolTipText("Save files that have selected check boxes"); 
		addButton(saveButton);				
        addCancelButton();	
	}	
	/**
	 * Set the tool tip on the cancel button.
	 * @param toolTip tool tip to set on the cancel button
	 */
	public void setCancelToolTipText(String toolTip) {
		setCancelToolTip(toolTip);
	}
	
	/**
	 * Show ChangedFilesDialog.
	 * @return whether the save button was selected; return false if the user
	 * canceled
	 */
	public boolean showDialog() {
		saveSelected = false;
		tool.showDialog(this);	
		return saveSelected;
	}
	private JPanel buildMainPanel() {
        JPanel outerPanel = new JPanel(new BorderLayout());
        outerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 5));

		filePanel = new DomainFilesPanel(fileList, "Changed Files");
		outerPanel.add(filePanel, BorderLayout.CENTER);

        return outerPanel;
	}

	private void save() {
		saveSelected=true;
		DomainFile[] files = filePanel.getSelectedDomainFiles();
		if (files.length > 0) {
			SaveTask task = new SaveTask(files);
			tool.execute(task);
		}
		else {
			close();
		}
	}

	@Override
    protected void cancelCallback() {
		close();
	}
	/**
	 * Task to save files.
	 */
	private class SaveTask extends Task {
		private DomainFile[] files;
		
		SaveTask(DomainFile[] files) {
			super(files.length>1?"Saving Files..." : "Saving File", 
				true, true, true);
			this.files = files;
		}
		
		@Override
        public void run(TaskMonitor monitor) {
			for (DomainFile file : files) {
				if (monitor.isCancelled()) {
			  		break;
			  	}
			  	String name = file.getName();
			  	monitor.setProgress(0);
				monitor.setMessage("Saving " + name);
				Msg.info(this, "Successfully saved file: " + name);
				try {
					file.save(monitor);
				}
				catch (CancelledException e) {
					// Move on (TODO: should we break?)
				}
				catch (IOException e) {
					Msg.showError(this, tool.getToolFrame(), "Error Saving File",
						"IO Exception while saving " + name, e);
				}
			}
			if (monitor.isCancelled()) {
				saveSelected=false;
			}
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					ChangedFilesDialog.this.close();
				}
			});
		}
	}


}
