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
package ghidra.features.base.quickfix;

import java.util.Map;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Generic base class for executable items to be displayed in a table that can be executed in bulk or
 * individually.
 */
public abstract class QuickFix {
	private long modificationNumber;
	private QuickFixStatus status = QuickFixStatus.NONE;
	private String statusMessage;
	protected final Program program;
	protected final String original;
	protected final String replacement;
	protected String current;

	protected QuickFix(Program program, String original, String replacement) {
		this.program = program;
		this.original = original;
		this.replacement = replacement;
		this.current = original;
		this.modificationNumber = program.getModificationNumber();
	}

	/**
	 * Returns the general name of the action to be performed.
	 * @return the general name of the action to be performed
	 */
	public abstract String getActionName();

	/**
	 * Returns the type of program element being affected (function, label, comment, etc.)
	 * @return the type of program element being affected 
	 */
	public abstract String getItemType();

	/**
	 * Returns the address of the affected program element if applicable or null otherwise.
	 * @return the address of the affected program element if applicable or null otherwise
	 */
	public abstract Address getAddress();

	/**
	 * Returns a path (the meaning of the path varies with the item type) associated with the 
	 * affected program element if applicable or null otherwise.
	 * @return a path associated with the affected program if applicable or null otherwise
	 */
	public abstract String getPath();

	/**
	 * Returns the original value of the affected program element.
	 * @return the original value of the affected program element.
	 */
	public String getOriginal() {
		return original;
	}

	/**
	 * Returns the current value of the affected program element. 
	 * @return the current value of the affected program element.
	 */
	public final String getCurrent() {
		refresh();
		return current;
	}

	protected void refresh() {
		if (program.getModificationNumber() == modificationNumber) {
			return;
		}
		modificationNumber = program.getModificationNumber();

		// once in an error status, it must stay that way (to distinguish it from the 
		// "not done" state, otherwise we would clear it when refresh the status)
		if (status == QuickFixStatus.ERROR) {
			return;
		}

		current = doGetCurrent();
		updateStatus();
	}

	/**
	 * Returns a preview of what the affected element will be if this item is applied.
	 * @return a preview of what the affected element will be if this item is applied
	 */
	public final String getPreview() {
		return replacement;
	}

	/**
	 * Executes the primary action of this QuickFix.
	 */
	public final void performAction() {
		if (status == QuickFixStatus.ERROR || status == QuickFixStatus.DONE) {
			return;
		}
		execute();
	}

	/**
	 * Returns the current {@link QuickFixStatus} of this item.
	 * @return the current {@link QuickFixStatus} of this item
	 */
	public final QuickFixStatus getStatus() {
		refresh();
		return status;
	}

	/**
	 * Returns the current status message of this item.
	 * @return the current status message of this item
	 */
	public String getStatusMessage() {
		if (statusMessage != null) {
			return statusMessage;
		}
		switch (status) {
			case DONE:
				return "Applied";
			case ERROR:
				return "Error";
			case NONE:
				return "Not Applied";
			case WARNING:
				return "Warning";
			case CHANGED:
				return "Target changed externally";
			case DELETED:
				return "Target no longer exists";
			default:
				return "";
		}
	}

	/**
	 * Sets the status of this item
	 * @param status the new {@link QuickFixStatus} for this item.
	 */
	public void setStatus(QuickFixStatus status) {
		setStatus(status, null);
	}

	/**
	 * Sets both the {@link QuickFixStatus} and the status message for this item. Typically, used
	 * to indicate a warning or error.
	 * @param status the new QuickFixStatus
	 * @param message the status message associated with the new status.
	 */
	public void setStatus(QuickFixStatus status, String message) {
		this.status = status;
		this.statusMessage = message;
	}

	public abstract ProgramLocation getProgramLocation();

	public Map<String, String> getCustomToolTipData() {
		return null;
		// do nothing - for subclasses to put specific info into the tooltip
	}

	/**
	 * Returns the current value of the item. 
	 * @return the current value of the item
	 */
	protected abstract String doGetCurrent();

	/**
	 * Executes the action.
	 */
	protected abstract void execute();

	/**
	 * QuickFix items can override this method if they want to do some special navigation when the
	 * table selection changes or the user double clicks (or presses {@code <return>} key) to 
	 * navigate.
	 * @param services the tool service provider
	 * @param fromSelectionChange true if this call was caused by the table selection changing
	 * @return true if this item handles the navigation and false if the QuickFix did not
	 * handle the navigation and the client should attempt to do generic navigation.
	 */
	protected boolean navigateSpecial(ServiceProvider services, boolean fromSelectionChange) {
		return false;
	}

	private void updateStatus() {
		QuickFixStatus newStatus = computeStatus();
		if (newStatus != status) {
			setStatus(newStatus);
			statusChanged(status);
		}
	}

	protected void statusChanged(QuickFixStatus newStatus) {
		// do nothing - used by subclasses
	}

	private QuickFixStatus computeStatus() {
		if (current == null) {
			return QuickFixStatus.DELETED;
		}
		if (current.equals(original)) {
			return QuickFixStatus.NONE;
		}
		if (current.equals(replacement)) {
			return QuickFixStatus.DONE;
		}
		return QuickFixStatus.CHANGED;
	}

}
