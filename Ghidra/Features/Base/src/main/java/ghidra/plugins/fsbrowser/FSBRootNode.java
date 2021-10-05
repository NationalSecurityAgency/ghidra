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
import java.util.ArrayList;
import java.util.List;

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
 * Since GTreeNodes are cloned during GTree filtering, and this class has a reference to an external
 * resource that needs managing, this class needs to keeps track of the original modelNode
 * and does all state modification using the modelNode's context.
 */
public class FSBRootNode extends FSBNode {

	private FileSystemRef fsRef;
	private FSBFileNode prevNode;
	private List<FSBRootNode> subRootNodes = new ArrayList<>();
	private FSBRootNode modelNode;

	FSBRootNode(FileSystemRef fsRef) {
		this(fsRef, null);
	}

	FSBRootNode(FileSystemRef fsRef, FSBFileNode prevNode) {
		this.fsRef = fsRef;
		this.prevNode = prevNode;
		this.modelNode = this;
	}

	@Override
	public GTreeNode clone() throws CloneNotSupportedException {
		FSBRootNode clone = (FSBRootNode) super.clone();
		clone.fsRef = null; // stomp on the clone's fsRef to force it to use modelNode's fsRef
		return clone;
	}

	@Override
	public void dispose() {
		releaseFSRefsIfModelNode();
		super.dispose();
	}

	void swapBackPrevModelNodeAndDispose() {
		if (this != modelNode) {
			modelNode.swapBackPrevModelNodeAndDispose();
			return;
		}
		int indexInParent = getIndexInParent();
		GTreeNode parent = getParent();
		parent.removeNode(this);
		parent.addNode(indexInParent, prevNode);
		dispose(); // releases the fsRef
	}

	public FileSystemRef getFSRef() {
		return modelNode.fsRef;
	}

	private void releaseFSRefsIfModelNode() {
		if (this != modelNode) {
			return;
		}
		for (FSBRootNode subFSBRootNode : subRootNodes) {
			subFSBRootNode.releaseFSRefsIfModelNode();
		}
		subRootNodes.clear();

		FileSystemService.getInstance().releaseFileSystemImmediate(fsRef);
		fsRef = null;
	}

	@Override
	public void updateFileAttributes(TaskMonitor monitor) throws CancelledException {
		if (this != modelNode) {
			modelNode.updateFileAttributes(monitor);
			return;
		}
		for (GTreeNode node : getChildren()) {
			monitor.checkCanceled();
			if (node instanceof FSBFileNode) {
				((FSBFileNode) node).updateFileAttributes(monitor);
			}
		}
	}

	@Override
	public String getName() {
		return modelNode.fsRef != null && !modelNode.fsRef.isClosed()
				? modelNode.fsRef.getFilesystem().getName()
				: " Missing ";
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
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		if (fsRef != null) {
			try {
				return FSBNode.createNodesFromFileList(fsRef.getFilesystem().getListing(null),
					monitor);
			}
			catch (IOException e) {
				FSUtilities.displayException(this, null, "Error Opening File System",
					"Problem generating children at root of file system", e);
			}
		}
		return List.of();
	}

	@Override
	public FSRL getFSRL() {
		return modelNode.fsRef.getFilesystem().getFSRL();
	}
}
