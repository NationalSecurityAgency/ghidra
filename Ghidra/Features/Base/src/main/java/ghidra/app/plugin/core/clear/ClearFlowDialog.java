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
package ghidra.app.plugin.core.clear;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.*;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.app.context.ListingActionContext;
import ghidra.util.HelpLocation;

/**
 * Dialog that shows options for "Clear Flow and Repair." User can choose to clear
 * symbols and data.  
 * Instructions and associated functions, references, etc. are always cleared.
 * Optional repair may also be selected.
 */
public class ClearFlowDialog extends DialogComponentProvider {

	private ClearPlugin plugin;
	private JPanel panel;
	private JCheckBox symbolsCb;
	private JCheckBox dataCb;
	private JCheckBox repairCb;
	private ListingActionContext context;

	/**
	 * Constructor
	 */
	ClearFlowDialog(ClearPlugin plugin) {
		super("Clear Flow");
		this.plugin = plugin;
		create();
		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation(plugin.getName(), "Clear_Flow_and_Repair"));
	}

	/**
	 * Gets called when the user clicks on the OK Action for the dialog.
	 */
	@Override
	public void okCallback() {
		close();

		plugin.clearFlowAndRepair(context, symbolsCb.isSelected(), dataCb.isSelected(),
			repairCb.isSelected());
	}

	/**
	 * Gets called when the user clicks on the Cancel Action for the dialog.
	 */
	@Override
	protected void cancelCallback() {
		close();
	}

	/**
	 * Create the main panel.
	 */
	private void create() {

		KeyListener listener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					e.consume();
					okCallback();
				}
			}
		};

		panel = new JPanel();
		panel.setLayout(new BorderLayout(10, 10));

		panel.add(new GLabel("Clear Flow Options:"), BorderLayout.NORTH);

		JPanel cbPanel = new JPanel();
		BoxLayout bl = new BoxLayout(cbPanel, BoxLayout.Y_AXIS);
		cbPanel.setLayout(bl);

		symbolsCb = new GCheckBox("Clear Symbols");
		dataCb = new GCheckBox("Clear Data");
		repairCb = new GCheckBox("Repair Flow");

		symbolsCb.setSelected(false);
		symbolsCb.addKeyListener(listener);
		dataCb.setSelected(false);
		dataCb.addKeyListener(listener);
		repairCb.setSelected(true);
		repairCb.addKeyListener(listener);

		cbPanel.add(symbolsCb);
		cbPanel.add(dataCb);
		cbPanel.add(repairCb);

		JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER));
		p.add(cbPanel);
		panel.add(p, BorderLayout.CENTER);
	}

	public void setProgramActionContext(ListingActionContext context) {
		this.context = context;
	}
}
