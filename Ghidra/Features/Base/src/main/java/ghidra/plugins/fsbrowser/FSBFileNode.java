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
package ghidra.plugins.fsbrowser;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.util.Date;
import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * GTreeNode that represents a file on a filesystem.
 */
public class FSBFileNode extends FSBNode {

	protected GFile file;
	protected boolean isEncrypted;
	protected boolean hasPassword;
	protected String symlinkDest;
	protected long lastModified;
	protected String filenameExtOverride;

	FSBFileNode(GFile file) {
		this.file = file;
	}

	@Override
	public void init(TaskMonitor monitor) {
		updateFileProps(monitor);
	}

	@Override
	public FSRL getFSRL() {
		return file.getFSRL();
	}

	@Override
	public GFile getGFile() {
		return file;
	}

	@Override
	public boolean isLeaf() {
		return true;
	}

	@Override
	public String getToolTip() {
		if (symlinkDest != null) {
			// unicode \u2192 is a -> right arrow
			return "%s \u2192 %s".formatted(getName(), symlinkDest);
		}

		long flen = file.getLength();
		String flenStr = flen >= 0 ? " - " + FileUtilities.formatLength(flen) : "";
		String lastModStr =
			lastModified > 0 ? " - " + FSUtilities.formatFSTimestamp(new Date(lastModified)) : "";
		String pwInfo = isEncrypted && !hasPassword ? " (missing password)" : "";

		return getName() + flenStr + lastModStr + pwInfo;
	}

	public boolean isSymlink() {
		return symlinkDest != null;
	}

	public String getFilenameExtOverride() {
		return filenameExtOverride;
	}

	@Override
	public String getFileExtension() {
		return filenameExtOverride != null && !filenameExtOverride.isEmpty()
				? filenameExtOverride
				: super.getFileExtension();
	}

	@Override
	public int hashCode() {
		return file.hashCode();
	}

	private void updateFileProps(TaskMonitor monitor) {
		FileAttributes fattrs = file.getFilesystem().getFileAttributes(file, monitor);
		isEncrypted = fattrs.get(IS_ENCRYPTED_ATTR, Boolean.class, false);
		hasPassword = fattrs.get(HAS_GOOD_PASSWORD_ATTR, Boolean.class, false);
		symlinkDest = fattrs.get(SYMLINK_DEST_ATTR, String.class, null);
		Date lastModDate = fattrs.get(MODIFIED_DATE_ATTR, Date.class, null);
		lastModified = lastModDate != null ? lastModDate.getTime() : 0;
		filenameExtOverride = fattrs.get(FILENAME_EXT_OVERRIDE, String.class, null);
	}

	@Override
	public void refreshNode(TaskMonitor monitor) throws CancelledException {
		boolean wasMissingPassword = hasMissingPassword();

		updateFileProps(monitor);

		if (wasMissingPassword != hasMissingPassword()) {
			getFSBRootNode().setCryptoStatusUpdated(true);
		}
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		return List.of();
	}

	/**
	 * Local copy of the original GFile's {@link FileAttributeType#IS_ENCRYPTED_ATTR} attribute.
	 * 
	 * @return boolean true if file needs a password to be read
	 */
	public boolean isEncrypted() {
		return isEncrypted;
	}

	/**
	 * Local copy of the original GFile's {@link FileAttributeType#HAS_GOOD_PASSWORD_ATTR} attribute.
	 * 
	 * @return boolean true if a password for the file has been found, false if missing the password
	 */
	public boolean hasPassword() {
		return hasPassword;
	}

	/**
	 * Returns true if this file is missing its password
	 * @return boolean true if this file is missing its password
	 */
	public boolean hasMissingPassword() {
		return isEncrypted && !hasPassword;
	}

	@Override
	public FSRL getLoadableFSRL() {
		return getFSRL();
	}

}
