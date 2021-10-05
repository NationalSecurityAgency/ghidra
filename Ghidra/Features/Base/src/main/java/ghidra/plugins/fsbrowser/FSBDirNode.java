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
import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.formats.gfilesystem.GFile;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * GTreeNode that represents a directory on a filesystem.
 */
public class FSBDirNode extends FSBFileNode {

	FSBDirNode(GFile dirFile) {
		super(dirFile);
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		try {
			return FSBNode.createNodesFromFileList(file.getListing(), monitor);
		}
		catch (IOException e) {
			// fall thru, return empty list
		}
		return List.of();
	}

	@Override
	public void updateFileAttributes(TaskMonitor monitor) {
		for (GTreeNode node : getChildren()) {
			if (node instanceof FSBFileNode) {
				((FSBFileNode) node).updateFileAttributes(monitor);
			}
			if (monitor.isCancelled()) {
				break;
			}
		}
		super.updateFileAttributes(monitor);
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

}
