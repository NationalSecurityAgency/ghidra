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
package ghidra.app.plugin.core.help;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.Transferable;
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.text.JTextComponent;

import docking.DialogComponentProvider;
import docking.DockingUtils;
import docking.dnd.GClipboard;
import docking.dnd.StringTransferable;
import docking.widgets.OptionDialog;
import docking.widgets.label.GIconLabel;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

public class AboutDomainObjectUtils {

	private static final MouseListener COPY_MOUSE_LISTENER = new PopupMouseListener();

	/**
	 * Displays an informational dialog about the specified domain object
	 *
	 * @param tool			 plugin tool
	 * @param domainFile     domain file to display information about
	 * @param metadata		 the metadata for the domainFile
	 * @param title          title to use for the dialog
	 * @param additionalInfo additional custom user information to append to
	 *                       the bottom of the dialog
	 * @param helpLocation	 the help location
	 */
	public static void displayInformation(PluginTool tool, DomainFile domainFile,
			Map<String, String> metadata, String title, String additionalInfo,
			HelpLocation helpLocation) {
		JComponent aboutComp = getAboutPanel(domainFile, metadata, additionalInfo);
		if (aboutComp == null) {
			return;
		}
		Dialog dialog = new Dialog(title, aboutComp);
		if (helpLocation != null) {
			dialog.setHelpLocation(helpLocation);
		}
		tool.showDialog(dialog);
	}

	private static void addInfo(JPanel panel, String name, String value) {
		if (value == null) {
			value = "?????";
		}
		JTextField nameField = new JTextField(name);
		nameField.setBorder(null);
		DockingUtils.setTransparent(nameField);
		nameField.setEditable(false);
		nameField.addMouseListener(COPY_MOUSE_LISTENER);

		JTextField valueField = new JTextField(value);
		valueField.setBorder(null);
		DockingUtils.setTransparent(valueField);
		valueField.setEditable(false);
		valueField.addMouseListener(COPY_MOUSE_LISTENER);

		panel.add(nameField);
		panel.add(valueField);
	}

	private static JComponent getAboutPanel(DomainFile domainFile, Map<String, String> metadata,
			String additionalInfo) {
		Font font = new Font("Monospaced", Font.PLAIN, 12);

		JPanel aboutPanel = new JPanel(new PairLayout());
		JScrollPane propertyScroll = new JScrollPane(aboutPanel);

		JPanel contentPanel = new JPanel(new BorderLayout(5, 5));
		contentPanel.add(propertyScroll, BorderLayout.CENTER);
		addInfo(aboutPanel, "Project File Name: ", domainFile.getName());
		long lastModified = domainFile.getLastModifiedTime();
		if (lastModified != 0) {
			addInfo(aboutPanel, "Last Modified:", (new Date(lastModified)).toString());
		}
		addInfo(aboutPanel, "Readonly:", Boolean.toString(domainFile.isReadOnly()));

		Iterator<String> it = metadata.keySet().iterator();
		while (it.hasNext()) {
			String key = it.next();
			String value = metadata.get(key);
			addInfo(aboutPanel, key + ":", value);
		}

		if (additionalInfo != null && additionalInfo.length() > 0) {
			JTextArea auxArea = new JTextArea(additionalInfo);
			auxArea.setFont(font);
			DockingUtils.setTransparent(auxArea);
			auxArea.setEditable(false);
			auxArea.setCaretPosition(0); // move cursor to BOF...
			JScrollPane sp = new JScrollPane(auxArea);
			sp.setBorder(BorderFactory.createTitledBorder(
				BorderFactory.createLineBorder(Color.black), "Additional Information"));
			sp.setPreferredSize(new Dimension(1, 175)); //width is ignored by border layout...

			JScrollBar sb = sp.getVerticalScrollBar();
			sb.setBorder(BorderFactory.createEtchedBorder());

			contentPanel.add(sp, BorderLayout.SOUTH);
		}

		JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 10));
		infoPanel.add(
			new GIconLabel(OptionDialog.getIconForMessageType(OptionDialog.INFORMATION_MESSAGE)));

		JPanel panel = new JPanel(new BorderLayout(5, 5));
		panel.add(infoPanel, BorderLayout.WEST);
		panel.add(contentPanel, BorderLayout.CENTER);

		Component[] comps = aboutPanel.getComponents();
		for (Component comp : comps) {
			comp.setFont(font);
		}
		aboutPanel.invalidate();

		panel.setPreferredSize(new Dimension(800, 800));

		return panel;
	}

	private static class Dialog extends DialogComponentProvider {
		Dialog(String title, JComponent workPanel) {
			super(title, false, false, true, false);
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

	private static class PopupMouseListener extends MouseAdapter {
		@Override
		public void mousePressed(MouseEvent e) {
			processPopupMouseEvent(e);
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			processPopupMouseEvent(e);
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			processPopupMouseEvent(e);
		}

		private void processPopupMouseEvent(MouseEvent e) {
			final Component component = e.getComponent();
			if (component == null) {
				return;
			}

			// get the bounds to see if the clicked point is over the component
			Rectangle bounds = component.getBounds(); // get bounds to get width and height

			if (component instanceof JComponent) {
				((JComponent) component).computeVisibleRect(bounds);
			}

			Point point = e.getPoint();
			boolean withinBounds = bounds.contains(point);

			if (e.isPopupTrigger() && withinBounds) {
				JPopupMenu popupMenu = new JPopupMenu();
				JMenuItem item = new JMenuItem("Copy");
				item.addActionListener(event -> writeDataToClipboard(component));
				popupMenu.add(item);
				popupMenu.show(component, e.getX(), e.getY());
			}
		}

		private static void writeDataToClipboard(Component component) {
			Clipboard systemClipboard = GClipboard.getSystemClipboard();
			try {
				systemClipboard.setContents(createContents(component), null);
			}
			catch (IllegalStateException e) {
				Msg.showInfo(AboutDomainObjectUtils.class, null, "Cannot Copy Data",
					"Unable to copy information to clipboard.  Please try again.");
			}
		}

		private static Transferable createContents(Component component) {
			// 
			// Structure based upon what is created in getAboutPanel()
			//
			Container parent = component.getParent();
			Component[] components = parent.getComponents();
			StringBuilder buffy = new StringBuilder();
			for (int i = 0; i < components.length; i++) {
				buffy.append(((JTextComponent) components[i]).getText());
				if (i != 0 && i % 2 != 0) {
					buffy.append('\n');
				}
				else {
					buffy.append('\t');
				}
			}
			return new StringTransferable(buffy.toString());
		}
	}
}
