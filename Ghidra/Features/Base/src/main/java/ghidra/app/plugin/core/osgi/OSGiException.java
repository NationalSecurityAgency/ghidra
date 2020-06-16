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
package ghidra.app.plugin.core.osgi;

import ghidra.util.exception.UsrException;

/**
 * Wrapper for exceptions originating with an OSGi operation.
 */
public class OSGiException extends UsrException {
	/**
	 * Create an exception with given {@code message} and {@code cause}.
	 * 
	 * @param message a contextual message
	 * @param cause the original exception
	 */
	public OSGiException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Create an exception with given {@code message}.
	 * 
	 * @param message a contextual message
	 */
	public OSGiException(String message) {
		super(message);
	}
}
