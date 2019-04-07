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
package ghidra.app.plugin.core.decompile.actions;

import java.util.List;

import ghidra.app.services.GraphService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.graph.GraphSelectionHandler;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.util.ProgramSelection;

class ASTGraphSelectionHandler implements GraphSelectionHandler {
	
	private GraphService graphService;
	private HighFunction hfunction;
	private int graphType;
	
	private boolean active = false;   // true if the window is active
    private boolean enabled = true;
	
	ASTGraphSelectionHandler(GraphService graphService, HighFunction hfunction, int graphType) {
		this.graphService = graphService;
		this.hfunction = hfunction;
		this.graphType = graphType;
	}

	public String getGraphType() {
		return graphType == ASTGraphTask.DATA_FLOW_GRAPH ?
				"AST Data Flow" : "AST Control Flow";
	}

	public boolean isActive() {
		return active;
	}

	public boolean isEnabled() {
		return enabled;
	}
	
	public void setActive(boolean active) {
		this.active = active;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public void locate(String location) {
		//Msg.debug(this, "locate1: " + location);
	}

	public String locate(Object locationObject) {
		
		if (graphType != ASTGraphTask.CONTROL_FLOW_GRAPH) {
			return null;
		}
		
		if (!(locationObject instanceof Address))
            return null;
        
        Address addr = (Address) locationObject;

		List<PcodeBlockBasic> blocks = hfunction.getBasicBlocks();
		for (PcodeBlockBasic block : blocks) {
			Address start = block.getStart();
			Address stop = block.getStop();
			if (addr.compareTo(start) >= 0 && addr.compareTo(stop) <= 0) {
	//Msg.debug(this, "index=" + block.getIndex());
				return Integer.toString(block.getIndex());
			}
		}
		return addr.toString();
	}

	public boolean notify(String notificationType) {
		//Msg.debug(this, "notify: " + notificationType);
		return false;
	}

	public void select(String[] selectedIndexes) {
		
		if (graphType != ASTGraphTask.CONTROL_FLOW_GRAPH) {
			return;
		}
		
		AddressSet set = new AddressSet();
		Address location = null;
		List<PcodeBlockBasic> blocks = hfunction.getBasicBlocks();
		for (String indexStr : selectedIndexes) {
			try {
				int index = Integer.parseInt(indexStr);
				PcodeBlockBasic block = blocks.get(index);
				Address start = block.getStart();
				set.addRange(start, block.getStop());
				if (location == null || start.compareTo(location) < 0) {
					location = start;
				}
			}
			catch (NumberFormatException e) {
				// continue
			}
		}
		if (location != null) {
			graphService.fireLocationEvent(location);
		}
		graphService.fireSelectionEvent(new ProgramSelection(set));
	}

	public String[] select(Object ghidraSelection) {
		// TODO Auto-generated method stub
		return null;
	}

	

}
