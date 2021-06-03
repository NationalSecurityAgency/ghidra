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

import java.io.IOException;
import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.formats.gfilesystem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A GTreeNode that represents the root of a {@link GFileSystem}, and keeps the
 * filesystem pinned in memory with its {@link FileSystemRef}.
 * <p>
 * The {@link FileSystemRef} is released when this node is {@link #dispose()}d.
 * <p>
 * Visible to just this package.
 */
public class FSBRootNode extends FSBNode {

	private FileSystemRef fsRef;
	private FSBFileNode prevNode;
	private List<FSBRootNode> subRootNodes = new ArrayList<>();

	FSBRootNode(FileSystemRef fsRef) {
		this.fsRef = fsRef;
	}

	FSBRootNode(FileSystemRef fsRef, FSBFileNode prevNode) {
		this.fsRef = fsRef;
		this.prevNode = prevNode;
	}

	public FileSystemRef getFSRef() {
		return fsRef;
	}

	public void releaseFSRefs() {
		for (FSBRootNode subFSBRootNode : subRootNodes) {
			subFSBRootNode.releaseFSRefs();
		}
		subRootNodes.clear();
		if (fsRef != null) {
			fsRef.close();
			fsRef = null;
		}
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getName() {
		return fsRef != null && !fsRef.isClosed() ? fsRef.getFilesystem().getName() : " Missing ";
	}

	@Override
	public String getToolTip() {
		return getName();
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	@Override
	public void dispose() {
		releaseFSRefs();
		super.dispose();
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		if (fsRef != null) {

			try {
				return FSBNode.getNodesFromFileList(fsRef.getFilesystem().getListing(null));
			}
			catch (IOException e) {
				FSUtilities.displayException(this, null, "Error Opening File System",
					"Problem generating children at root of file system", e);
			}
		}
		return Collections.emptyList();
	}

	@Override
	public FSRL getFSRL() {
		return fsRef.getFilesystem().getFSRL();
	}

	public FSBFileNode getPrevNode() {
		return prevNode;
	}

	public List<FSBRootNode> getSubRootNodes() {
		return subRootNodes;
	}
}
