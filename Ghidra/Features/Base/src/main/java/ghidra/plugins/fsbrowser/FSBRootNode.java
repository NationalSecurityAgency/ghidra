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
 * Since GTreeNodes are cloned during GTree filtering, and this class has a reference to an external
 * resource that needs managing, this class needs to keeps track of the original modelNode
 * and does all state modification using the modelNode's context.
 */
public class FSBRootNode extends FSBNode {

	private RefdFile rootDir; // do not use RefdFile.close(), the FsRef will be extracted and closed manually
	private FSBFileNode prevNode;
	private FSBRootNode modelNode;
	private boolean cryptoStatusUpdated;
	private Icon icon;

	FSBRootNode(RefdFile rootDir) {
		this(rootDir, null);
	}

	FSBRootNode(RefdFile rootDir, FSBFileNode prevNode) {
		super(FSBComponentProvider.getDescriptiveFSName(rootDir));

		this.rootDir = rootDir;
		this.prevNode = prevNode;
		this.modelNode = this;
		this.icon = FSBComponentProvider.getFSIcon(rootDir.fsRef.getFilesystem(), prevNode == null,
			FSBIcons.getInstance());
	}

	@Override
	public GTreeNode clone() throws CloneNotSupportedException {
		FSBRootNode clone = (FSBRootNode) super.clone();
		clone.rootDir = null; // stomp on the clone's fsRef to force it to use modelNode's fsRef
		return clone;
	}

	@Override
	public void dispose() {
		releaseFSRefIfModelNode();
		super.dispose();
	}

	@Override
	public void init(TaskMonitor monitor) throws CancelledException {
		setChildren(generateChildren(monitor));
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return icon;
	}

	public void setCryptoStatusUpdated(boolean cryptoStatusUpdated) {
		this.cryptoStatusUpdated = cryptoStatusUpdated;
	}

	boolean isCryptoStatusUpdated() {
		return cryptoStatusUpdated;
	}

	public void swapBackPrevModelNodeAndDispose() {
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

	@Override
	public GFile getGFile() {
		return rootDir.file;
	}

	public FileSystemRef getFSRef() {
		return modelNode.rootDir != null ? modelNode.rootDir.fsRef : null;
	}

	private void releaseFSRefIfModelNode() {
		if (this != modelNode || rootDir == null) {
			return;
		}
		FileSystemService.getInstance().releaseFileSystemImmediate(rootDir.fsRef);
		rootDir = null;
	}

	@Override
	public void refreshNode(TaskMonitor monitor) throws CancelledException {
		if (this != modelNode) {
			modelNode.refreshNode(monitor);
			return;
		}
		refreshChildren(monitor);
		if (cryptoStatusUpdated) {
			// do something to refresh children's status that may have been affected by crypto update 
		}
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
		if (rootDir != null) {
			try {
				return FSBNode.createNodesFromFileList(rootDir.file.getListing(), monitor);
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
		return modelNode != null && modelNode.rootDir != null
				? modelNode.rootDir.file.getFSRL()
				: null;
	}

	public FSBNode getGFileFSBNode(GFile file, TaskMonitor monitor) {
		List<GFile> pathParts = splitGFilePath(file);
		List<GFile> rootPathParts = splitGFilePath(rootDir.file);
		// TODO: ensure pathParts has a prefix that equals rootPathParts
		FSBNode fileNode = this;
		for (int i = rootPathParts.size() /* skip root */; fileNode != null &&
			i < pathParts.size(); i++) {
			try {
				fileNode = fileNode.findMatchingNode(pathParts.get(i), monitor);
			}
			catch (CancelledException e) {
				return null;
			}
		}
		return fileNode;
	}

	public FSRL getContainer() {
		// allows the import of the file container of a filesystem image
		if ( rootDir != null && rootDir.file.getParentFile() == null ) {
			return rootDir.fsRef.getFilesystem().getFSRL().getContainer();
		}
		return null;
	}

	private List<GFile> splitGFilePath(GFile f) {
		List<GFile> result = new ArrayList<>();
		while (f != null) {
			result.add(0, f);
			f = f.getParentFile();
		}
		return result;
	}

	public FSRL getProgramProviderFSRL(FSRL fsrl) {
		if (rootDir != null) {
			GFileSystem fs = rootDir.fsRef.getFilesystem();
			if (fs instanceof GFileSystemProgramProvider programProviderFS) {
				try {
					GFile gfile = fs.lookup(fsrl.getPath());
					if (gfile != null && programProviderFS.canProvideProgram(gfile)) {
						return fsrl;
					}
				}
				catch (IOException e) {
					// ignore error and fall thru
				}
			}
		}
		return null;
	}

	@Override
	public FSRL getLoadableFSRL() {
		FSRL ppFSRL = getProgramProviderFSRL(getFSRL());
		if (ppFSRL != null) {
			return ppFSRL;
		}
		return getContainer();
	}

}
