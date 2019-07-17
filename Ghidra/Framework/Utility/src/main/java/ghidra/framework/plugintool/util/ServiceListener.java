/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.plugintool.util;

/**
 * Notifications for when services are added to or removed from a PluginTool. 
 */
public interface ServiceListener {
	/**
	 * Notifies the listener that a service has been added to the tool.
	 * @param interfaceClass the interface class that the given service implements.
	 * @param service the implementation of the service.
	 */
	void serviceAdded(Class<?>  interfaceClass, Object service);
	/**
	 * Notifies the listener that a service has been removed from the tool.
	 * @param interfaceClass the interface class that the given service implements.
	 * @param service the implementation of the service.
	 */
	void serviceRemoved(Class<?> interfaceClass, Object service);

}
