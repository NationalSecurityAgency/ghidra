/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.clipboard;

import ghidra.app.util.ClipboardType;
import ghidra.util.HelpLocation;

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.widgets.list.ListPanel;


public class CopyPasteSpecialDialog extends DialogComponentProvider {

	private ListPanel listPanel;
	private JPanel mainPanel; 
	
	private List<?> availableTypes;
	private Object selectedType;

	public CopyPasteSpecialDialog(ClipboardPlugin plugin, List<?> availableTypes, String title) {
		super(title, true);
		this.availableTypes = availableTypes;

		mainPanel = createPanel();
		addWorkPanel(mainPanel);

		addOKButton();
		addCancelButton();

		setHelpLocation(new HelpLocation("ClipboardPlugin", "Copy_Special"));
	}
	
	private JPanel createPanel() {
		mainPanel = new JPanel(new BorderLayout());

		listPanel = new ListPanel();
		listPanel.setListData(availableTypes.toArray());
		JList list = listPanel.getList();
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.setVisibleRowCount(Math.max(3, Math.min(availableTypes.size(), 7)));
		list.setSelectedIndex(0);
		list.addKeyListener(new KeyAdapter() {
			@Override
            public void keyPressed(KeyEvent evt) {
				if (evt.getKeyCode() == KeyEvent.VK_ENTER) {
					evt.consume();
					okCallback();
				}
			}
		});
		list.addMouseListener(new MouseAdapter() {
			@Override
            public void mousePressed(MouseEvent evt) {
				if (evt.getButton() == MouseEvent.BUTTON1  &&  evt.getClickCount() == 2) {
					evt.consume();
					okCallback();
				}
			}
		});

		mainPanel.add(listPanel, BorderLayout.CENTER);
		mainPanel.setBorder(new TitledBorder("Select Format"));

		return mainPanel;
	}


	@Override
    protected void okCallback() {
		close();
		selectedType = listPanel.getSelectedValue();
	}

	@Override
    protected void cancelCallback() {
		close();
	}

	public ClipboardType getSelectedType() {
	    return (ClipboardType) selectedType;
	}

}
