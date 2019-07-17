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

import java.awt.Component;

import docking.widgets.OptionDialog;
import ghidra.framework.model.DomainFile;
import ghidra.util.exception.VersionException;

public class VersionExceptionHandler {

	public static boolean isUpgradeOK(Component parent, DomainFile domainFile, String actionName,
			VersionException ve) {
		String contentType = domainFile.getContentType();
		if (domainFile.isReadOnly() || ve.getVersionIndicator() != VersionException.OLDER_VERSION ||
			!ve.isUpgradable()) {
			showVersionError(parent, domainFile.getName(), contentType, actionName, ve);
			return false;
		}
		String filename = domainFile.getName();

		// make sure the user wants to upgrade

		if (domainFile.isVersioned() && !domainFile.isCheckedOutExclusive()) {
			showNeedExclusiveCheckoutDialog(parent, filename, contentType, actionName);
			return false;
		}

		int userChoice = showUpgradeDialog(parent, ve, filename, contentType, actionName);
		if (userChoice != OptionDialog.OPTION_ONE) {
			return false;
		}
		if (domainFile.isCheckedOut()) {
			userChoice = showWarningDialog(parent, filename, contentType, actionName);
			if (userChoice != OptionDialog.OPTION_ONE) {
				return false;
			}
		}

		return true;
	}

	private static void showNeedExclusiveCheckoutDialog(final Component parent, String filename,
			String contentType, String actionName) {

		Msg.showError(VersionExceptionHandler.class, parent, actionName + " Failed!",
			"Unable to " + actionName + " " + contentType + ": " + filename + "\n \n" +
				"An upgrade of the " + contentType +
				" data is required, however, you must have an exclusive checkout\n" +
				"to upgrade a shared file!\n \n" +
				"NOTE: If you are unable to obtain an exclusive checkout, you may be able to " +
				actionName + "\nthe file with an older version of Ghidra.");
	}

	private static int showUpgradeDialog(final Component parent, VersionException ve,
			final String filename, final String contentType, final String actionName) {
		final String detailMessage =
			ve.getDetailMessage() == null ? "" : "\n" + ve.getDetailMessage();

		String title = "Upgrade " + contentType + " Data? " + filename;
		String message = "The " + contentType + " file you are attempting to " + actionName +
			" is an older version." + detailMessage + "\n \n" + "Would you like to Upgrade it now?";
		return OptionDialog.showOptionDialog(parent, title, message, "Upgrade",
			OptionDialog.QUESTION_MESSAGE);
	}

	private static int showWarningDialog(final Component parent, String filename,
			String contentType, String actionName) {

		String title = "Upgrade Shared " + contentType + " Data? " + filename;
		String message = "This " + contentType +
			" file is shared with other users.  If you upgrade this file,\n" +
			"other users will not be able to read the new version until they upgrade to \n" +
			"the same version of Ghidra. Do you want to continue?";
		return OptionDialog.showOptionDialog(parent, title, message, "Upgrade",
			OptionDialog.WARNING_MESSAGE);
	}

	public static void showVersionError(final Component parent, final String filename,
			final String contentType, final String actionName, VersionException ve) {

		int versionIndicator = ve.getVersionIndicator();
		final String versionType;
		if (versionIndicator == VersionException.NEWER_VERSION) {
			versionType = " newer";
		}
		else if (versionIndicator == VersionException.OLDER_VERSION) {
			versionType = "n older";
		}
		else {
			versionType = "n unknown";
		}

		String upgradeMsg = "";
		if (ve.isUpgradable()) {
			upgradeMsg = " (data upgrade is possible)";
		}

		Msg.showError(VersionExceptionHandler.class, parent, actionName + " Failed!",
			"Unable to " + actionName + " " + contentType + ": " + filename + "\n \n" +
				"File was created with a" + versionType + " version of Ghidra" + upgradeMsg);
	}
}
