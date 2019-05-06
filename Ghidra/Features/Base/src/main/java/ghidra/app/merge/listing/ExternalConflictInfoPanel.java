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
package ghidra.app.merge.listing;

import java.awt.BorderLayout;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.widgets.label.GDHtmlLabel;
import ghidra.app.merge.util.ConflictUtility;

/**
 * <code>ExternalConflictInfoPanel</code> appears above the 4 listings in the ListingMergeWindow.
 * It indicates the Externals phase.
 * It also indicates how many groups of conflicts to resolve,
 * how many individual conflict need resolving for that named external, 
 * and how far you are along in the process.
 */
public class ExternalConflictInfoPanel extends JPanel {

	private final static long serialVersionUID = 1;
	private String conflictType;
	private int conflictNum;
	private int totalConflicts;
	private String versionTitle;
	private String labelPathName;
	private JLabel eastLabel;
	private JLabel westLabel;

	/**
	 * Creates a new <code>ExternalConflictInfoPanel</code> to use above the listings.
	 */
	public ExternalConflictInfoPanel() {
		super();
		create();
	}

	private void create() {

		setLayout(new BorderLayout());
		setBorder(BorderFactory.createTitledBorder("Resolve External Location Conflict"));

		westLabel = new GDHtmlLabel("<html></html>");
		eastLabel = new GDHtmlLabel("<html></html>");
		add(westLabel, BorderLayout.WEST);
		add(eastLabel, BorderLayout.EAST);
	}

	/**
	 * Returns a string indicating the current phase of the External merge.
	 */
	String getConflictType() {
		return conflictType;
	}

	/**
	 * Returns the current external label or function's pathname being resolved as displayed by this panel.
	 */
	String getLabelPathName() {
		return labelPathName;
	}

	/**
	 * Call this to set the phase of the Listing merge that you are in currently.
	 * @param conflictType the type of conflict being resolved by this phase
	 * (for example, Symbols).
	 */
	void setConflictType(String conflictType) {
		this.conflictType = conflictType;
		TitledBorder tBorder = (TitledBorder) getBorder();
		tBorder.setTitle("Resolve " + conflictType + " Conflict");
	}

	void setConflictInfo(int conflictNum, int totalConflicts) {
		this.conflictNum = conflictNum;
		this.totalConflicts = totalConflicts;
		updateEast();
	}

	/**
	 * Updates the externals name info.
	 * @param externalNum number for the current externals being resolved
	 * @param totalExternals total number of externals to resolve
	 */
	void setExternalName(String versionTitle, String labelPathName) {
		this.versionTitle = versionTitle;
		this.labelPathName = labelPathName;
		updateWest();
	}

	private void addCount(StringBuffer buf, int value) {
		buf.append("<font color=\"#990000\">" + value + "</font>");
	}

	private void addName(StringBuffer buf, String name) {
		buf.append("<font color=\"#990000\">" + name + "</font>");
	}

	private void updateWest() {
		StringBuffer buf = new StringBuffer();
		buf.append(" Conflict for ");
		addName(buf, versionTitle);
		buf.append(" version of external ");
		addName(buf, labelPathName);
		westLabel.setText(ConflictUtility.wrapAsHTML(buf.toString()));
	}

	private void updateEast() {
		StringBuffer buf = new StringBuffer();
		buf.append("External Conflict #");
		addCount(buf, conflictNum);
		buf.append(" of ");
		addCount(buf, totalConflicts);
		buf.append(". ");
		eastLabel.setText(ConflictUtility.wrapAsHTML(buf.toString()));
	}

}
