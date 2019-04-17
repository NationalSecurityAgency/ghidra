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

import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.graph.*;
import ghidra.util.exception.GraphException;


/**
 * Service for getting a Graph display.
 *
 */
@ServiceInfo(/* defaultProvider = NONE, */ description = "Get a Graph Display")
public interface GraphService {

    /**
     * Create Graph Data compatible with this graph service
     */
    GraphData createGraphContent();

    /**
     * Get a graph display.
     * @param newDisplay a new graph window will be used if true.
     * @throws GraphException if unable to obtain a graph window.
     */
    GraphDisplay getGraphDisplay(boolean newDisplay) throws GraphException;
    
	/**
	 * Get a graph display.
	 * @throws GraphException if unable to obtain a graph window.
	 */
	GraphDisplay getGraphDisplay() throws GraphException;
	
	/**
	 * Send specified selection object to all connected graphs
	 * that understand the concept of "selection."
	 * @param selection selection object to interpret
	 */
	void setSelection(Object selection);
	
	/**
	 * Send specified location object to all connected graphs that understand
	 * the concept of "location."
	 * @param location location object to interpret
	 */
	void setLocation(Object location);
	
	/**
	 * Set the selection for all connected graphs and fire a selection event
	 * for Ghidra. 
	 * @param selection selection object to interpret
	 */
	void fireSelectionEvent(Object selection);
	/**
	 * Set the location for all connected graphs and fire a location event
	 * for Ghidra.
	 * @param location location object to interpret
	 */
	void fireLocationEvent(Object location);
	/**
     * Handle notification from graph.
     * @param notificationType command generated from graph
     * @param handler associated graph handler
     * @return true if notification was handled and there is no need for any other 
     * graph service provider to notified.
     */
	boolean fireNotificationEvent(String notificationType, GraphSelectionHandler handler);
}
