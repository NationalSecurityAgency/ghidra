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
package ghidra.framework.model;

import ghidra.framework.plugintool.PluginTool;

/**
 * Represents a connection between a producer tool and a
 * consumer tool.
 */
public interface ToolConnection {

	/**
	 * Get the tool that produces an event
	 * @return the tool
	 */
	public PluginTool getProducer();

	/**
	 * Get the tool that consumes an event
	 * @return the tool
	 */
	public PluginTool getConsumer();

	/**
	 * Get the list of event names that is an intersection
	 * between what the producer produces and what the
	 * consumers consumes.
	 * 
	 * @return an array of event names
	 */
	public String[] getEvents();

	/**
	 * Connect the tools for the given event name.
	 * 
	 * @param eventName name of event to connect
	 * 
	 * @throws IllegalArgumentException if eventName is not valid for this
	 * producer/consumer pair.
	 */
	public void connect(String eventName);

	/**
	 * Break the connection between the tools for the
	 * given event name.
	 * 
	 * @param eventName name of event to disconnect
	 * 
	 * @throws IllegalArgumentException if eventName is not valid for this
	 * producer/consumer pair.
	 */
	public void disconnect(String eventName);

	/**
	 * Return whether the tools are connected for the
	 * given event name.
	 * 
	 * @param eventName name of event to check
	 * @return true if the tools are connected by eventName.
	 */
	public boolean isConnected(String eventName);

}
