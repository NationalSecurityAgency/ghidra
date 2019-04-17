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

import ghidra.util.exception.UsrException;

 
/**
 * Exception thrown when a an error occurs during the construction
 * of a plugin. 
 *
 */
public class PluginConstructionException extends UsrException {

	/**
	 * Construct a new exception.
	 * @param className name of the plugin class that failed to load
	 * @param details details of the construction failure
	 */
	public PluginConstructionException(String className, String details) {
		super("Cannot load plugin"+className+" :"+details);
	}

}
