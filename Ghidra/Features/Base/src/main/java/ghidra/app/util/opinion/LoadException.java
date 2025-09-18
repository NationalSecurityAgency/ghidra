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
package ghidra.app.util.opinion;

import java.io.IOException;

/**
 * Thrown when a {@link Loader#load(ghidra.app.util.opinion.Loader.ImporterSettings) load}
 * fails in an expected way.  The supplied message should explain the reason. 
 */
public class LoadException extends IOException {

	/**
	 * Create a new {@link LoadException} with the given message
	 * 
	 * @param message The exception message
	 */
	public LoadException(String message) {
		super(message);
	}
	
	/**
	 * Create a new {@link LoadException} with the given message and cause
	 * 
	 * @param message The exception message
	 * @param cause The exception cause
	 */
	public LoadException(String message, Throwable cause) {
		super(message, cause);
	}
	
	/**
	 * Create a new {@link LoadException} with the given cause
	 * 
	 * @param cause The exception cause
	 */
	public LoadException(Throwable cause) {
		super(cause);
	}
}
