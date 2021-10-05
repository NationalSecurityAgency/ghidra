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

import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * GTreeNode that represents a file on a filesystem.
 */
public class FSBFileNode extends FSBNode {

	protected GFile file;
	protected boolean isEncrypted;
	protected boolean hasPassword;

	FSBFileNode(GFile file) {
		this.file = file;
	}

	@Override
	public FSRL getFSRL() {
		return file.getFSRL();
	}

	@Override
	public boolean isLeaf() {
		return true;
	}

	@Override
	public int hashCode() {
		return file.hashCode();
	}

	@Override
	protected void updateFileAttributes(TaskMonitor monitor) {
		FileAttributes fattrs = file.getFilesystem().getFileAttributes(file, monitor);
		isEncrypted = fattrs.get(IS_ENCRYPTED_ATTR, Boolean.class, false);
		hasPassword = fattrs.get(HAS_GOOD_PASSWORD_ATTR, Boolean.class, false);
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

	/**
	 * Returns true if this node's password status has changed, calling for a complete refresh
	 * of the status of all files in the file system.
	 *  
	 * @param monitor {@link TaskMonitor}
	 * @return boolean true if this nodes password status has changed
	 */
	public boolean needsFileAttributesUpdate(TaskMonitor monitor) {
		if (hasMissingPassword()) {
			updateFileAttributes(monitor);
			return hasPassword; // if true then the attribute has changed and everything should be refreshed
		}
		return false;
	}

}
