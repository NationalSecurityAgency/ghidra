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
package ghidra.app.plugin.core.datamgr.tree;

import java.util.List;

import docking.widgets.tree.GTreeLazyNode;
import docking.widgets.tree.GTreeNode;

/**
 * A single interface for unifying the handling of nodes that can be manipulated during
 * cut/copy/paste operations.
 */
public abstract class DataTypeTreeNode extends GTreeLazyNode {

	/**
	 * Returns true if this node can be cut and moved to a different location.
	 * @return true if this node can be cut and moved to a different location.
	 */
	public abstract boolean canCut();

	/**
	 * Returns true if this nodes handles paste operations
	 * @return true if this nodes handles paste operations
	 */
	public abstract boolean canPaste(List<GTreeNode> pastedNodes);

	/**
	 * Signals to this node that it has been cut during a cut operation, for example, like during
	 * a cut/paste operation.
	 * @param isCut true signals that the node has been cut; false that it is not cut.
	 */
	public abstract void setNodeCut(boolean isCut);

	/**
	 * Return true if the node has been cut.
	 * @return true if the node has been cut.
	 */
	public abstract boolean isCut();

	/**
	 * Returns the ArchiveNode for this tree node.
	 * @return the ArchiveNode for this tree node.
	 */
	public abstract ArchiveNode getArchiveNode();

	/**
	 * Returns true if this node is from an archive that can be modified.
	 * @return true if this node is from an archive that can be modified.
	 */
	public abstract boolean isModifiable();

	/**
	 * Returns true if this node can be deleted
	 * @return true if this node can be deleted
	 */
	public abstract boolean canDelete();

}
