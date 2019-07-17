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
package ghidra.app.services;

import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.GroupPath;

/**
 * Service provided by the program tree plugin to get the current view 
 * (address set shown in the Code Browser), 
 * and the name of the tree currently being viewed.
 * 
 * 
 *
 */
@ServiceInfo(defaultProvider = ProgramTreePlugin.class, description = "Get the currently viewed address set")
public interface ProgramTreeService {
	
	/**
	 * Get the name of the tree currently being viewed.
	 */
	public String getViewedTreeName();
	
	/**
	 * Set the current view to that of the given name. If treeName is not
	 * a known view, then nothing happens.
	 * @param treeName name of the view
	 */
	public void setViewedTree(String treeName);
	
	/**
	 * Get the address set of the current view (what is currently being shown in
	 * the Code Browser).
	 */
	public AddressSet getView(); 
	
	/**
	 * Set the selection to the given group paths.
	 * @param gps paths to select
	 */
	public void setGroupSelection(GroupPath[] gps);
}
