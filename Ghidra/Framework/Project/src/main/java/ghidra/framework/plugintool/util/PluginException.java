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
 *Exception thrown if plugin was not found.
 */
public class PluginException extends UsrException {

	/**
	* Construct PluginException with a detail message.
	* @param className class name of the plugin
	* @param details the reason the addPlugin failed.
	 */
	public PluginException(String className, String details) {
		super("Can't add plugin: " + className + ".  " + details);
	}

	/**
	 * Construct a PluginException with the given message.
	 * @param message message that is returned in the getMessage() method
	 */
	public PluginException(String message) {
		super(message);
	}

	/**
	 * Construct a PluginException with the given message and cause.
	 * @param message the exception message
	 * @param cause the exception cause
	 */
	public PluginException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Creates a new PluginException by appending the message from 
	 * this exception to the message of the given exception if it
	 * is not null. If e is null, returns this exception.
	 * @param e exception whose message will be appended to this
	 * exceptions message if e is not null
	 * @return this exception if e is null, or a new exception
	 */
	public PluginException getPluginException(PluginException e) {
		if (e == null) {
			return this;
		}
		return new PluginException(e.getMessage() + "\n" + getMessage());
	}
}
