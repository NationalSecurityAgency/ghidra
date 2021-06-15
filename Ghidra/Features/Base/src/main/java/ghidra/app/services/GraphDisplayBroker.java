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

import java.util.*;

import ghidra.app.plugin.core.graph.GraphDisplayBrokerListener;
import ghidra.app.plugin.core.graph.GraphDisplayBrokerPlugin;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.service.graph.*;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra service interface for managing and directing graph output.  It purpose is to discover
 * available graphing display providers and (if more than one) allow the user to select the currently
 * active graph consumer.  Clients that generate graphs don't have to worry about how to display them
 * or export graphs. They simply send their graphs to the broker and register for graph events if
 * they want interactive support.
 */
@ServiceInfo(defaultProvider = GraphDisplayBrokerPlugin.class, description = "Get a Graph Display")
public interface GraphDisplayBroker {

	/**
	 * Gets the currently active GraphDisplayProvider that will be used to display/export graphs
	 * @return the currently active GraphDisplayProvider
	 */
	public GraphDisplayProvider getDefaultGraphDisplayProvider();

	/**
	 * Adds a listener for notification when the set of graph display providers change or the currently
	 * active graph display provider changes 
	 * @param listener the listener to be notified
	 */
	public void addGraphDisplayBrokerListener(GraphDisplayBrokerListener listener);

	/**
	 * Removes the given listener
	 * @param listener the listener to no longer be notified of changes
	 */
	public void removeGraphDisplayBrokerLisetener(GraphDisplayBrokerListener listener);

	/**
	 * A convenience method for getting a {@link GraphDisplay} from the currently active provider
	 * @param reuseGraph if true, the provider will attempt to re-use a current graph display
	 * @param monitor the {@link TaskMonitor} that can be used to cancel the operation
	 * @return a {@link GraphDisplay} object to sends graphs to be displayed or exported.
	 * @throws GraphException thrown if an error occurs trying to get a graph display
	 */
	public default GraphDisplay getDefaultGraphDisplay(boolean reuseGraph, TaskMonitor monitor)
			throws GraphException {
		return getDefaultGraphDisplay(reuseGraph, Collections.emptyMap(), monitor);
	}

	/**
	 * A convenience method for getting a {@link GraphDisplay} from the currently active provider
	 * 
	 * <p>This method allows users to override default graph properties for the graph provider 
	 * being created.  See the graph provider implementation for a list of supported properties
	 * 
	 * @param reuseGraph if true, the provider will attempt to re-use a current graph display
	 * @param properties a {@code Map} of property key/values that can be used to customize the display
	 * @param monitor the {@link TaskMonitor} that can be used to cancel the operation
	 * @return a {@link GraphDisplay} object to sends graphs to be displayed or exported.
	 * @throws GraphException thrown if an error occurs trying to get a graph display
	 */
	public GraphDisplay getDefaultGraphDisplay(boolean reuseGraph, Map<String, String> properties,
			TaskMonitor monitor)
			throws GraphException;

	/**
	 * Checks if there is at least one {@link GraphDisplayProvider} in the system.
	 * @return true if there is at least one {@link GraphDisplayProvider}
	 */
	public boolean hasDefaultGraphDisplayProvider();

	/**
	 * Gets the {@link GraphDisplayProvider} with the given name
	 * @param name the name of the GraphDisplayProvider to get
	 * @return the GraphDisplayProvider with the given name or null if none with that name exists.
	 */
	public GraphDisplayProvider getGraphDisplayProvider(String name);

	/**
	 * Returns a list of all discovered {@link AttributedGraphExporter}.
	 * @return  a list of all discovered {@link AttributedGraphExporter}.
	 */
	public List<AttributedGraphExporter> getGraphExporters();

	/**
	 * Returns the {@link AttributedGraphExporter} with the given name or null in no exporter with
	 * that name is known
	 * 
	 * @param name the name of the exporter to retrieve
	 * @return  the {@link AttributedGraphExporter} with the given name or null if no exporter with
	 * that name is known
	 */
	public AttributedGraphExporter getGraphExporters(String name);

}
