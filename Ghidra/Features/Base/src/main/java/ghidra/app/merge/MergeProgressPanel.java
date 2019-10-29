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
package ghidra.app.merge;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.HashMap;

import javax.swing.*;
import javax.swing.border.Border;

import docking.widgets.label.GIconLabel;
import docking.widgets.label.GLabel;
import ghidra.util.Msg;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;

/**
 * The MergeProgressPanel displays the name of each merge phase along with an icon indicating
 * whether the phase is Pending, In Progress or Completed.
 */
public class MergeProgressPanel extends JPanel {

	public static ImageIcon DEFINED_ICON = ResourceManager.loadImage("images/bullet_green.png");
	public static ImageIcon IN_PROGRESS_ICON = ResourceManager.loadImage("images/right.png");
	public static ImageIcon COMPLETED_ICON =
		ResourceManager.loadImage("images/checkmark_green.gif");
	private HashMap<String, JLabel> imageMap = new HashMap<>();
	private static int INDENT_IN_PIXELS = 20;

	/**
	 * Constructor for a merge progress panel.
	 */
	public MergeProgressPanel() {
		setLayout(new VerticalLayout(5));
		add(getProgressTitlePanel());
	}

	private JPanel getProgressTitlePanel() {
		JPanel phasesTitlePanel = new JPanel();
		Border insideBorder = BorderFactory.createEmptyBorder(0, 0, 2, 0);
		Border outsideBorder = BorderFactory.createMatteBorder(0, 0, 2, 0, Color.BLUE);
		Border compoundBorder = BorderFactory.createCompoundBorder(outsideBorder, insideBorder);
		phasesTitlePanel.setBorder(compoundBorder);
		BoxLayout bl = new BoxLayout(phasesTitlePanel, BoxLayout.X_AXIS);
		phasesTitlePanel.setLayout(bl);
		phasesTitlePanel.add(Box.createHorizontalStrut(5));
		phasesTitlePanel.add(new GLabel("Merge Status"));
		phasesTitlePanel.add(Box.createHorizontalStrut(15));
		phasesTitlePanel.add(new GLabel("( "));
		phasesTitlePanel.add(new GIconLabel(DEFINED_ICON));
		phasesTitlePanel.add(new GLabel(" = Pending"));
		phasesTitlePanel.add(Box.createHorizontalStrut(10));
		phasesTitlePanel.add(new GIconLabel(IN_PROGRESS_ICON));
		phasesTitlePanel.add(new GLabel(" = In Progress"));
		phasesTitlePanel.add(Box.createHorizontalStrut(10));
		phasesTitlePanel.add(new GIconLabel(COMPLETED_ICON));
		phasesTitlePanel.add(new GLabel(" = Completed"));
		phasesTitlePanel.add(new GLabel(" )"));
		phasesTitlePanel.add(Box.createHorizontalStrut(5));
		return phasesTitlePanel;
	}

	/**
	 * Adds a new phase name and its associated icon to the panel.
	 * The last string in the array will be the name displayed for this phase.
	 * @param phase array of strings indicating this phase. 
	 * The first string indicates the primary phase. EAch subsequent string indicates 
	 * another sub-phase of the phase indicated by the previous string.
	 * The last string indicates this phase.
	 * @return the panel that was added which displays this phase's name and status
	 */
	public JPanel addInfo(String[] phase) {
		int phaseDepth = phase.length - 1;
		JLabel imageLabel = new GIconLabel(DEFINED_ICON);
		JPanel labelPanel = new JPanel();
		labelPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
		BoxLayout bl = new BoxLayout(labelPanel, BoxLayout.X_AXIS);
		labelPanel.setLayout(bl);
		labelPanel.add(Box.createHorizontalStrut(INDENT_IN_PIXELS * phaseDepth));
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(imageLabel);
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(new GLabel(phase[phaseDepth]));
		imageMap.put(getPhaseString(phase), imageLabel);
		add(labelPanel);
		return labelPanel;
	}

	/**
	 * Indicates a particular phase or sub-phase whose status icon is to be changed to 
	 * indicate that it is in progress.
	 * @param phase array which indicates this phase or sub-phase.
	 */
	public void setInProgress(String[] phase) {
		JLabel iconLabel = imageMap.get(getPhaseString(phase));
		if (iconLabel != null) {
			iconLabel.setIcon(IN_PROGRESS_ICON);
		}
	}

	/**
	 * Indicates a particular phase or sub-phase whose status icon is to be changed to 
	 * indicate that it is completed.
	 * @param phase array which indicates this phase or sub-phase.
	 */
	public void setCompleted(String[] phase) {
		JLabel iconLabel = imageMap.get(getPhaseString(phase));
		if (iconLabel != null) {
			iconLabel.setIcon(COMPLETED_ICON);
		}
	}

	/**
	 * Gets a string based on the array for a phase or sub-phase.
	 * This string can then be used to identify the particular phase.
	 * @param phase array which indicates the phase or sub-phase.
	 * @return a string representation for the phase.
	 */
	private String getPhaseString(String[] phase) {
		StringBuffer buf = new StringBuffer();
		buf.append(phase[0]);
		for (int i = 1; i < phase.length; i++) {
			buf.append(":" + phase[i]);
		}
		return buf.toString();
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		MergeProgressPanel panel = new MergeProgressPanel();

		String[] MEMORY = new String[] { "Memory" };
		String[] PROGRAM_TREE = new String[] { "Program Tree" };
		String[] DATA_TYPES = new String[] { "Data Types" };
		String[] PROGRAM_CONTEXT = new String[] { "Program Context" };
		String[] LISTING = new String[] { "Listing" };
		String[] BYTES = new String[] { "Listing", "Bytes" };
		String[] CODE_UNITS = new String[] { "Listing", "Code Units" };
		String[] FUNCTIONS = new String[] { "Listing", "Functions" };
		String[] SYMBOLS = new String[] { "Listing", "Symbols" };
		String[] COMMENTS =
			new String[] { "Listing", "Comments, References & User Defined Properties" };
		String[] EXTERNAL_PROGRAM = new String[] { "External Program" };
		String[] PROPERTY_LIST = new String[] { "Property List" };

		panel.addInfo(MEMORY);
		panel.addInfo(PROGRAM_TREE);
		panel.addInfo(DATA_TYPES);
		panel.addInfo(PROGRAM_CONTEXT);
		panel.addInfo(LISTING);
		panel.addInfo(BYTES);
		panel.addInfo(CODE_UNITS);
		panel.addInfo(FUNCTIONS);
		panel.addInfo(SYMBOLS);
		panel.addInfo(COMMENTS);
		panel.addInfo(EXTERNAL_PROGRAM);
		panel.addInfo(PROPERTY_LIST);

//		try {
//			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
//		} catch (Exception e) {
//		}
		JFrame frame = new JFrame();
		frame.setSize(800, 400);
		frame.setVisible(true);

		frame.getContentPane().setLayout(new BorderLayout());
		frame.getContentPane().add(panel, BorderLayout.CENTER);
		frame.validate();
		frame.setVisible(true);

		try {
			panel.setInProgress(MEMORY);
			Thread.sleep(2000);
			panel.setCompleted(MEMORY);
//			panel.updateIcon(PROGRAM_TREE, IN_PROGRESS_ICON);
			Thread.sleep(2000);
//			panel.updateIcon(PROGRAM_TREE, COMPLETED_ICON);
//			panel.updateIcon(DATA_TYPES, IN_PROGRESS_ICON);
//			Thread.sleep(2000);
//			panel.updateIcon(DATA_TYPES, COMPLETED_ICON);
//			panel.updateIcon(PROGRAM_CONTEXT, IN_PROGRESS_ICON);
//			Thread.sleep(2000);
//			panel.updateIcon(PROGRAM_CONTEXT, COMPLETED_ICON);
//			panel.updateIcon(LISTING, IN_PROGRESS_ICON);
//			panel.updateIcon(BYTES, IN_PROGRESS_ICON);
//			Thread.sleep(2000);
//			panel.updateIcon(BYTES, COMPLETED_ICON);
//			panel.updateIcon(CODE_UNITS, IN_PROGRESS_ICON);
//			Thread.sleep(2000);
//			panel.updateIcon(CODE_UNITS, COMPLETED_ICON);
//			panel.updateIcon(FUNCTIONS, IN_PROGRESS_ICON);
//			Thread.sleep(2000);
//			panel.updateIcon(FUNCTIONS, COMPLETED_ICON);
//			panel.updateIcon(SYMBOLS, IN_PROGRESS_ICON);
//			Thread.sleep(2000);
//			panel.updateIcon(SYMBOLS, COMPLETED_ICON);
//			panel.updateIcon(COMMENTS, IN_PROGRESS_ICON);
//			Thread.sleep(2000);
//			panel.updateIcon(COMMENTS, COMPLETED_ICON);
//			panel.updateIcon(LISTING, COMPLETED_ICON);
//			panel.updateIcon(EXTERNAL_PROGRAM, IN_PROGRESS_ICON);
//			Thread.sleep(2000);
//			panel.updateIcon(EXTERNAL_PROGRAM, COMPLETED_ICON);
//			panel.updateIcon(PROPERTY_LIST, IN_PROGRESS_ICON);
//			Thread.sleep(2000);
//			panel.updateIcon(PROPERTY_LIST, COMPLETED_ICON);
//			Thread.sleep(2000);
		}
		catch (InterruptedException e) {
			Msg.error(null, "Unexpected Exception: " + e.getMessage(), e);
		}
		frame.setVisible(false);
		System.exit(0);
	}

}
