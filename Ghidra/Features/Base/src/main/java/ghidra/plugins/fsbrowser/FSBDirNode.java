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
import java.util.Collections;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.formats.gfilesystem.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * GTreeNode that represents a directory on a filesystem.
 * <p>
 * Visible to just this package.
 */
public class FSBDirNode extends FSBNode {
	private FSRL fsrl;

	FSBDirNode(FSRL fsrl) {
		this.fsrl = fsrl;
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		try (RefdFile dir = FileSystemService.getInstance().getRefdFile(fsrl, monitor)) {
			return FSBNode.getNodesFromFileList(dir.file.getListing());
		}
		catch (IOException e) {
			Msg.showError(this, null, "loadChildren", e);
		}
		return Collections.emptyList();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getName() {
		return fsrl.getName();
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	@Override
	public String getToolTip() {
		return fsrl.getName();
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	@Override
	public int hashCode() {
		return fsrl.hashCode();
	}

}
