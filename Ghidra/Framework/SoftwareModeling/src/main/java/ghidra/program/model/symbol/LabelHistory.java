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
package ghidra.program.model.symbol;

import java.util.Date;

import ghidra.program.model.address.Address;

/**
 * Container for history information about what happened to a label.
 */
public class LabelHistory {
	/**
	 * Label added.
	 */
	public static final byte ADD 	 = (byte)0;
	/**
	 * Label removed.
	 */
	public static final byte REMOVE = (byte)1;
	/**
	 * Label renamed.
	 */
	public static final byte RENAME = (byte)2;

	private Address addr;
	private String labelStr;
	private byte actionID;
	private Date modificationDate;
	private String userName;
	
	/**
	 * Construct a new LabelHistory object.
	 * @param addr address of the label change
	 * @param userName name of user who made the change
	 * @param actionID either ADD, REMOVE, or RENAME
	 * @param labelStr label string
	 * @param modificationDate date of the change
	 */	
	public LabelHistory(Address addr, String userName, 
						byte actionID, String labelStr,
						Date modificationDate) {

		this.addr = addr;
		this.userName = userName;
		this.actionID = actionID;
		this.labelStr = labelStr;
		this.modificationDate = modificationDate;
	}
	/**
	 * Get address for this label history object.
	 */
	public Address getAddress() {
		return addr;
	}

	/**
	 * Get the user that made the change.
	 */
	public String getUserName() {
		return userName;
	}
	/**
	 * Get the label string for this label history object.
	 */
	public String getLabelString() {
		return labelStr;
	}
	/**
	 * Get the action ID for this label history object.
	 * @return ADD, REMOVE, or RENAME
	 */
	public byte getActionID() {
		return actionID;
	}
	/**
	 * Get the modification date
	 */
	public Date getModificationDate() {
		return modificationDate;
	}
		
}
