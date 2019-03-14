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
package ghidra.app.plugin.core.programtree;

import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

import java.awt.dnd.DnDConstants;

/**
 * Helper class to interpret the drop operation as a Move/Copy
 * operation versus the reorder.
 */
class DnDMoveManager {

    private ProgramDnDTree tree;
    private ReorderManager reorderDDMgr;

    /**
     * Constructor
     */
    DnDMoveManager(ProgramDnDTree tree) {
        this.tree = tree;
        reorderDDMgr = new ReorderManager(tree);
    }
    
    /**
     * Return true if the destNode can accept the dropNodes.
     */
    boolean isDropSiteOk(ProgramNode destinationNode, ProgramNode[] dropNodes,
                         int dropAction, int relativeMousePos) {

        // must be able to drop all nodes, or none at all
        for ( int i = 0; i < dropNodes.length; i++ ) {
            if ( !canDropNode( destinationNode, dropNodes[i], dropAction, relativeMousePos ) ) {
                return false;
            }
        }
        return true;
    }
    
    private boolean canDropNode( ProgramNode destinationNode, ProgramNode dropNode,
            int dropAction, int relativeMousePosition ) {
        
        Group dragGroup = dropNode.getGroup();        
        if (dragGroup.equals(destinationNode.getGroup())) {
            return false; // can't drop a group onto itself
        }
        if (relativeMousePosition != 0 ) {
            return reorderDDMgr.isDropSiteOk(destinationNode, dropNode, dropAction,
                relativeMousePosition);
        }
        
        // this is for a normal drop on the node
        if (destinationNode.isFragment()) {
            return checkDestFragment(destinationNode, dropNode, dropAction);
        }
        
        // check for destination module already containing drop Module or Fragment
        ProgramModule destModule = destinationNode.getModule();
        if (dropNode.isFragment() && destModule.contains(dropNode.getFragment())) {
            return false;
        }
        if (dropNode.isModule()) {
            ProgramModule dropModule = dropNode.getModule();
            if (destModule.contains(dropNode.getModule())) {
                return false;
            }
            if (dropModule.isDescendant(destModule)) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Add the given data to the destination node.
     * @param destNode destination node for the data.
     * @param dropNode data to add
     * @param dropAction move or copy
     * @param relativeMousePos mouse position within the node:
	 *  			-1 --> above node,
	 *				 0 --> at the node
	 *				 1 --> below the node
     */
    void add(ProgramNode destNode, ProgramNode[] dropNodes, int dropAction, int relativeMousePos) 
            throws NotFoundException, CircularDependencyException, DuplicateGroupException {
	
		if (relativeMousePos != 0) {
			reorderDDMgr.add(destNode, dropNodes, dropAction, relativeMousePos);
			return;
		}

		String operation = (dropAction == DnDConstants.ACTION_MOVE)? "Move" : "Copy";
		int transactionID = tree.startTransaction(operation);
		if (transactionID < 0) {
			return;
		}
		
		try {
		    
            for ( int i = 0; i < dropNodes.length; i++ ) {            
                boolean ok = true;
                
                // this is a normal drag/drop on the node
                if (destNode.isFragment()) {
                    ok = addToFragment(destNode, dropNodes[i]);
                }
                else {
                    addToModule(destNode, dropNodes[i], dropAction);
                }
                if (ok) {
                    tree.addSelectionPath(destNode.getTreePath());
                }
            }
		} finally {
			tree.endTransaction(transactionID, true);
		}
    }

	//////////////////////////////////////////////////////////////////////////
	
    /**
     * Check whether the drop is ok given that destNode is a fragment.
     * @param destNode fragment node
     * @param dropNode node that is getting dropped
     * @param dropAction move or copy action
     * @return true if the destNode is a valid drop target
     */
	private boolean checkDestFragment(ProgramNode destNode, 
		ProgramNode dropNode, int dropAction) {
			
			
        if (dropAction != DnDConstants.ACTION_MOVE) {
            return false;
        }
        if (dropNode.isFragment()) {
            return true;   // Fragment -> Fragment means Merge Fragments
        }
        ProgramModule dropModule = dropNode.getModule();
        if (dropModule.isDescendant(destNode.getFragment())) {
            return false;
        }
        return true; // Module -> Fragment means flatten Module, i.e.,
                     // move all code units from descendant fragments to
                    // destination fragment...
	}
	
	private boolean addToFragment(ProgramNode destNode, ProgramNode dropNode) {
		// dropNode can be either fragment or module
		ProgramFragment destFrag = destNode.getFragment();
		try {
		    tree.mergeGroup(dropNode.getGroup(), destFrag);
		    tree.removeSelectionPath(dropNode.getTreePath());
		    return true;
		} catch (Exception e) {
		    Msg.showError(this, null, "Error", "Error Moving Fragments", e);
		}
		return false;
	}

	private void addToModule(ProgramNode destNode, ProgramNode dropNode,
							 int dropAction)
		throws DuplicateGroupException, NotFoundException, CircularDependencyException {
		// destination is a Module
		ProgramModule destModule = destNode.getModule();
		ProgramModule parentModule = dropNode.getParentModule();
		if (!destNode.wasVisited()) {
		    tree.visitNode(destNode);
		}
		if (dropNode.isFragment()) {
		    ProgramFragment fragment = dropNode.getFragment();
		    if (dropAction == DnDConstants.ACTION_COPY) {
		        destModule.add(fragment);
		    }
		    else {
		        destModule.reparent(fragment.getName(), parentModule);
		    }
		}
		else {
		    ProgramModule module = dropNode.getModule();
		    if (dropAction == DnDConstants.ACTION_COPY) {
		        destModule.add(module);
		    }
		    else {
		        destModule.reparent(module.getName(), parentModule);
		    }
		    if (tree.isExpanded(destNode.getTreePath())) {
		        tree.groupAdded(module); // need to add the
		                // group now so that the expansion can be
		                // matched
		    }
		}
		// don't match the expansion state unless the destination
		// node is already expanded
		if (tree.isExpanded(destNode.getTreePath())) {
		    // apply expansion state of the dropped node to the new node.
		    ProgramNode newnode = tree.getChild(destNode, dropNode.getName());
		    if (newnode != null) {
		        tree.matchExpansionState(dropNode, newnode);
		    }
		}
	}
}
