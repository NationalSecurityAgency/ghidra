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
import ghidra.program.model.address.*;
import ghidra.util.HTMLUtilities;

/**
 * <code>ConflictInfoPanel</code> appears above the 4 listings in the ListingMergeWindow.
 * It indicates the current sub-phase of the ListingMerge (Code Units, Functions, Symbols, etc.).
 * It also indicates how many groups of conflicts to resolve (typically address ranges),
 * how many individual conflict need resolving for that address range,
 * and how far you are along in the process.
 */
public class ConflictInfoPanel extends JPanel {

	private final static long serialVersionUID = 1;
	private String conflictType;
	private int conflictNum;
	private int totalConflicts;
	private Address minAddress;
	private Address maxAddress;
	private long addressNum;
	private long totalAddresses;
	private boolean isCodeUnit;
	private JLabel eastLabel;
	private JLabel westLabel;
	private String registerName;

	/**
	 * Creates a new <code>ConflictInfoPanel</code> to use above the listings.
	 */
	public ConflictInfoPanel() {
		super();
		create();
	}

	private void create() {

		setLayout(new BorderLayout());
		setBorder(BorderFactory.createTitledBorder("Resolve Current Conflict"));

		westLabel = new GDHtmlLabel("<html></html>");
		eastLabel = new GDHtmlLabel("<html></html>");
		add(westLabel, BorderLayout.WEST);
		add(eastLabel, BorderLayout.EAST);
	}

	/**
	 * Returns a string indicating the current phase of the Listing merge.
	 */
	String getConflictType() {
		return conflictType;
	}

	/**
	 * Returns the current address being resolved as displayed by this panel.
	 */
	Address getAddress() {
		return minAddress;
	}

	/**
	 * Returns the current address being resolved as displayed by this panel.
	 */
	AddressRange getAddressRange() {
		return new AddressRangeImpl(minAddress, maxAddress);
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
		updateWest();
	}

	/**
	 * Sets the current register name when this panel is being used for register conflict information.
	 * @param registerName the register name.
	 */
	void setRegisterInfo(String registerName) {
		this.registerName = registerName;
		westLabel.setText(ConflictUtility.wrapAsHTML(getRegisterText()));
	}

	private String getRegisterText() {
		StringBuffer buf = new StringBuffer();
		buf.append("Register: ");
		buf.append(ConflictUtility.getEmphasizeString(registerName));
		buf.append("");
		return buf.toString();
	}

	/**
	 * Updates the address info.
	 * @param address current address being resolved
	 * @param addressNum number for the current address being resolved
	 * @param totalAddresses total number of addresses to resolve
	 */
	void setAddressInfo(Address address, long addressNum, long totalAddresses) {
		isCodeUnit = false;
		this.minAddress = address;
		this.maxAddress = address;
		this.addressNum = addressNum;
		this.totalAddresses = totalAddresses;
		updateEast();
	}

	/**
	 * Updates the address info.
	 * @param addressRange current address range being resolved.
	 * @param addressNum number for the current address range being resolved
	 * @param totalAddresses total number of addresses to resolve
	 */
	void setCodeUnitInfo(AddressRange addressRange, int addressNum, int totalAddresses) {
		isCodeUnit = true;
		this.minAddress = addressRange.getMinAddress();
		this.maxAddress = addressRange.getMaxAddress();
		this.addressNum = addressNum;
		this.totalAddresses = totalAddresses;
		updateEast();
	}

	private void addCount(StringBuffer buf, long value) {
		buf.append("<font color=\"#990000\">" + value + "</font>");
	}

	private void addAddress(StringBuffer buf, Address addr) {
		buf.append(
			"<font color=\"#990000\">" + HTMLUtilities.escapeHTML(addr.toString()) + "</font>");
	}

	private void updateWest() {
		StringBuffer buf = new StringBuffer();
		buf.append("Conflict #");
		addCount(buf, conflictNum);
		buf.append(" of ");
		addCount(buf, totalConflicts);
		if (isCodeUnit) {
			buf.append(" for address range: ");
			addAddress(buf, minAddress);
			buf.append("-");
			addAddress(buf, maxAddress);
		}
		else if (minAddress != null) {
			buf.append(" @ address: ");
			addAddress(buf, minAddress);
		}
		westLabel.setText(ConflictUtility.wrapAsHTML(buf.toString()));
	}

	private void updateEast() {
		StringBuffer buf = new StringBuffer();
		if (isCodeUnit) {
			buf.append("Address range #");
		}
		else {
			buf.append("Address #");
		}
		addCount(buf, addressNum);
		buf.append(" of ");
		addCount(buf, totalAddresses);
		buf.append(" with conflicts");
		eastLabel.setText(ConflictUtility.wrapAsHTML(buf.toString()));
	}

}
