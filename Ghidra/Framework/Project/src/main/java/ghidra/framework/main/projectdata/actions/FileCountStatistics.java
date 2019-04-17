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
package ghidra.framework.main.projectdata.actions;

import java.awt.Component;

import docking.widgets.OptionDialog;
import docking.widgets.OptionDialogBuilder;

class FileCountStatistics {

	private int fileCount;
	private int readOnlySkipped;
	private int generalFailure;
	private int fileInUse;
	private int versionedDeclined;
	private int checkedOutVersioned;
	private int deleted;

	FileCountStatistics(int fileCount) {
		this.fileCount = fileCount;
	}

	public void incrementDeleted() {
		deleted++;
	}

	public int getTotalDeleted() {
		return deleted;
	}

	public int getFileCount() {
		return fileCount;
	}

	public void incrementFileCount(int size) {
		fileCount += size;
	}

	public void incrementReadOnly() {
		readOnlySkipped++;
	}

	public void incrementGeneralFailure() {
		generalFailure++;
	}

	public void incrementFileInUse() {
		fileInUse++;
	}

	public void incrementVersioned() {
		versionedDeclined++;
	}

	public void incrementCheckedOutVersioned() {
		checkedOutVersioned++;
	}

	public void showReport(Component parent) {
		// don't show results if only one file processed.
		if (getTotalProcessed() == 1) {
			return;
		}
		// don't show results if all selected files deleted
		if (deleted == fileCount) {
			return;
		}

		String message = buildReportMessage();
		OptionDialogBuilder builder = new OptionDialogBuilder("Delete Files Summary", message);
		builder.setMessageType(OptionDialog.INFORMATION_MESSAGE);
		builder.show(parent);
	}

	private String buildReportMessage() {
		StringBuilder builder = new StringBuilder();
		builder.append("<html>");
		builder.append(deleted).append(" file(s) deleted!");
		if (getTotalNotDeleted() > 0) {
			builder.append("<br><br>Files not deleted:<br>");
			builder.append("<table style='margin-left: 20pt;'>");
			if (fileInUse > 0) {
				builder.append("<tr><td>In Use: </td><td>").append(fileInUse).append("</td></tr>");
			}
			if (versionedDeclined > 0) {
				builder.append("<tr><td>   Versioned: </td><td>").append(versionedDeclined).append(
					"</td></tr>");
			}
			if (checkedOutVersioned > 0) {
				builder.append("<tr><td>Checked-out: </td><td>").append(checkedOutVersioned).append(
					"</td></tr>");
			}
			if (readOnlySkipped > 0) {
				builder.append("<tr><td>Read only: </td><td>").append(readOnlySkipped).append(
					"</td></tr>");
			}
			if (generalFailure > 0) {
				builder.append("<tr><td>Other: </td><td>").append(generalFailure).append(
					"</td></tr>");
			}
			builder.append("</table>");
		}
		return builder.toString();
	}

	private int getTotalProcessed() {
		return readOnlySkipped + generalFailure + fileInUse + versionedDeclined +
			checkedOutVersioned + deleted;
	}

	private int getTotalNotDeleted() {
		return getTotalProcessed() - deleted;
	}
}
