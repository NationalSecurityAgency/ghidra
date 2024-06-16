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
package ghidra.feature.vt.api.util;

import java.io.IOException;

import ghidra.app.util.dialog.CheckoutDialog;
import ghidra.app.util.task.ProgramOpener;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.remote.User;
import ghidra.program.database.ProgramDB;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * {@link VTSessionFileUtil} provides methods for checking {@link VTSessionDB} source and
 * destination program files prior to being opened and used during session instantiation.
 */
public class VTSessionFileUtil {

	// static utility class
	private VTSessionFileUtil() {
	}

	/**
	 * Validate a VT source program to ensure it meets minimum criteria to open with a VTSession.
	 * The following validation checks are performed:
	 * <ul>
	 * <li>file must correspond to a ProgramDB</li>
	 * </ul>
	 * If an error is thrown it is intended to be augmented for proper presentation.
	 * 
	 * @param file VT Session source program domain file 
	 * @param includeFilePathInError if true file path will be appended to any exception throw
	 * @throws IllegalArgumentException if any VT source program file criteria is not satisfied
	 */
	public static void validateSourceProgramFile(DomainFile file, boolean includeFilePathInError)
			throws IllegalArgumentException {
		String error = null;
		if (!ProgramDB.class.isAssignableFrom(file.getDomainObjectClass())) {
			error = "Source file does not correspond to a Program";
		}
		if (error != null) {
			if (includeFilePathInError) {
				error += ":\n" + file.getPathname();
			}
			throw new IllegalArgumentException(error);
		}
	}

	/**
	 * Validate a VT destination program to ensure it meets minimum criteria to open with a VTSession.
	 * GUI mode only: If file is versioned and not checked-out the user may be prompted to perform
	 * an optional checkout of the file.  Prompting for checkout will not occur if this method
	 * is invoked from the Swing thread or operating in a headless mode.
	 * The following validation checks are performed:
	 * <ul>
	 * <li>file must correspond to a ProgramDB</li>
	 * <li>file must be contained within the active project</li>
	 * <li>file must not be marked read-only</li>
	 * <li>if file is versioned it must be checked-out (user may be prompted to do this)</li>
	 * </ul>
	 * If an error is thrown it is intended to be augmented for proper presentation.
	 * 
	 * @param file VT Session destination program domain file 
	 * @param includeFilePathInError if true file path will be appended to any exception throw
	 * @param silent if user interaction should not be performed.  This should be true if
	 * filesystem lock is currently held.
	 * @throws IllegalArgumentException if any VT destination program file criteria is not satisfied
	 */
	public static void validateDestinationProgramFile(DomainFile file,
			boolean includeFilePathInError, boolean silent) throws IllegalArgumentException {
		String error = null;
		if (!ProgramDB.class.isAssignableFrom(file.getDomainObjectClass())) {
			error = "Destination file does not correspond to a Program";
		}
		else {
			DomainFolder folder = file.getParent();
			if (folder == null || !folder.isInWritableProject()) {
				error = "Destination file must be from active project";
			}
			else if (file.isReadOnly()) {
				error = "Destination file must not be read-only";
			}
			else if (file.isVersioned()) {
				if (!silent) {
					doOptionalDestinationProgramCheckout(file);
				}
				if (!file.isCheckedOut()) {
					error = "Versioned destination file must be checked-out for update";
				}
			}
		}
		if (error != null) {
			if (includeFilePathInError) {
				error += ":\n" + file.getPathname();
			}
			throw new IllegalArgumentException(error);
		}
	}

	/**
	 * Determine if the specified {@link DomainFile} will permit update.
	 * @param file domain file
	 * @return true if file permits update else false
	 */
	public static boolean canUpdate(DomainFile file) {
		DomainFolder folder = file.getParent();
		if (folder == null || !folder.isInWritableProject()) {
			return false;
		}
		if (file.isReadOnly()) {
			return false;
		}
		if (file.isVersioned()) {
			return false;
		}
		return true;
	}

	private static void doOptionalDestinationProgramCheckout(DomainFile file) {

		if (SystemUtilities.isInHeadlessMode() || !file.canCheckout()) {
			return;
		}

		User user = file.getParent().getProjectData().getUser();
		CheckoutDialog dialog = new CheckoutDialog(file, user);
		dialog.setTitle("VT Destination Program not Checked Out");
		if (dialog.showDialog() == CheckoutDialog.CHECKOUT) { // uses Swing thread
			CheckoutDestinationProgramTask task =
				new CheckoutDestinationProgramTask(file, dialog.exclusiveCheckout());
			TaskLauncher.launch(task);
		}
	}

	private static class CheckoutDestinationProgramTask extends Task {

		private DomainFile file;
		boolean exclusiveCheckout;

		CheckoutDestinationProgramTask(DomainFile file, boolean exclusiveCheckout) {
			super("Checking Out " + file, true, true, true, true);
			this.file = file;
			this.exclusiveCheckout = exclusiveCheckout;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			monitor.setMessage("Checking Out " + file);
			try {
				if (!file.checkout(exclusiveCheckout, monitor)) {
					Msg.showError(ProgramOpener.class, null, "Checkout Failed",
						"Exclusive checkout failed for: " + file +
							"\nOne or more users have file checked out!");
				}
			}
			catch (IOException e) {
				Msg.showError(ProgramOpener.class, null, "Checkout Failed",
					"Checkout failed for: " + file + "\n" + e.getMessage());
			}
			catch (CancelledException e) {
				// ignore
			}
		}

	}

}
