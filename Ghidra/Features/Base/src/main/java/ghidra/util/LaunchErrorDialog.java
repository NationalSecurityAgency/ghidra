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
package ghidra.util;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;

import javax.swing.*;

import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.label.*;
import generic.util.WindowUtilities;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

public class LaunchErrorDialog extends JDialog {

	private boolean isCancelled;
	private final URL url;
	private final URL fileURL;

	public LaunchErrorDialog(URL url, URL fileURL) {
		super(DockingWindowManager.getActiveInstance().getRootFrame(), true);
		this.url = url;
		this.fileURL = fileURL;
		setTitle("Unable to Launch Manual Viewer");

		JComponent workPanel = createWorkPanel();
		getContentPane().add(workPanel);

		pack();

		Window activeWindow = DockingWindowManager.getActiveInstance().getActiveWindow();
		Point centerPoint = WindowUtilities.centerOnComponent(activeWindow, this);
		setLocation(centerPoint);

		DockingWindowManager.setHelpLocation(workPanel,
			new HelpLocation("ShowInstructionInfoPlugin", "Show_Processor_Manual"));
	}

	private JComponent createWorkPanel() {
		JPanel rootPanel = new JPanel(new BorderLayout());

		JPanel workPanel = new JPanel();
		workPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		workPanel.setLayout(new BoxLayout(workPanel, BoxLayout.Y_AXIS));

		JPanel innerPanel = createInnerWidgetPanel();
		workPanel.add(Box.createVerticalGlue());
		workPanel.add(innerPanel);
		workPanel.add(Box.createVerticalGlue());

		rootPanel.add(workPanel);
		rootPanel.add(createButtonPanel(), BorderLayout.SOUTH);

		return rootPanel;
	}

	private JPanel createInnerWidgetPanel() {
		JPanel innerPanel = new JPanel(new BorderLayout());

		JLabel iconLabel =
			new GIconLabel(OptionDialog.getIconForMessageType(OptionDialog.WARNING_MESSAGE));
		iconLabel.setVerticalAlignment(SwingConstants.TOP);

		JPanel widgetPanel = new JPanel(new VerticalLayout(5));
		widgetPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JTextField urlField = new JTextField(40);
		urlField.setText(url.toString());
		Color backgroundColor = urlField.getBackground();
		urlField.setEditable(false);
		urlField.setBackground(backgroundColor);

		JTextField fileField = new JTextField(40);
		fileField.setText((fileURL == null) ? "" : fileURL.toString());
		fileField.setEditable(false);
		fileField.setBackground(backgroundColor);

		JPanel textFieldPanel = new JPanel(new PairLayout(2, 0));
		textFieldPanel.add(new GLabel("URL: "));
		textFieldPanel.add(urlField);
		textFieldPanel.add(new GLabel("File: "));
		textFieldPanel.add(fileField);

		widgetPanel.add(
			new GHtmlLabel("<html>Unable to launch a viewer for the manual below.<br><br>" +
				"Click <b>Edit Settings</b> to change the manual viewer launch settings, or <br>" +
				"click <b>Cancel</b> to abort launching a manual viewer (" +
				"<font size=\"2\">See the help (F1) for more information).</font>"));
		widgetPanel.add(Box.createHorizontalStrut(5));
		widgetPanel.add(textFieldPanel);

		JLabel copyLabel = new GHtmlLabel("<html><font size=\"2\"><i>Ctrl-C to copy</i></font>");
		copyLabel.setHorizontalAlignment(SwingConstants.CENTER);
		widgetPanel.add(copyLabel);

		widgetPanel.setMaximumSize(widgetPanel.getPreferredSize());

		innerPanel.add(widgetPanel);
		innerPanel.add(iconLabel, BorderLayout.WEST);

		return innerPanel;
	}

	private JPanel createButtonPanel() {
		JPanel buttonPanel = new JPanel();

		JButton editButton = new JButton("Edit Settings");
		editButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				editCallback();
			}
		});

		JButton cancelButton = new JButton("Cancel");
		cancelButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				cancelCallback();
			}
		});

		buttonPanel.add(editButton);
		buttonPanel.add(Box.createHorizontalStrut(5));
		buttonPanel.add(cancelButton);

		return buttonPanel;
	}

	protected void editCallback() {
		isCancelled = false;
		setVisible(false);
	}

	protected void cancelCallback() {
		isCancelled = true;
		setVisible(false);
	}

	boolean isCancelled() {
		return isCancelled;
	}

}
