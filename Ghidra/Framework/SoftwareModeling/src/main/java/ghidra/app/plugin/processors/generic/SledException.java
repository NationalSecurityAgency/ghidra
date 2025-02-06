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
/*
 * Created on Sep 24, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.plugin.processors.generic;

/**
 * 
 *
 * Exceptions generated from parsing the SLED/SSL configuration files (load time)
 */
public class SledException extends RuntimeException {
	/**
	 * @param e
	 */
	public SledException(Exception e) {
		super(e.getMessage());
	}

	/**
	 * <p>Constructs a SledException with no detail message.
	 */
	public SledException() {
		super();
	}
	
	/**
	 * <p>Constructs a SledException with the specified
	 * detail message.
	 *
	 * @param message The message.
	 */
	public SledException(String message) {
		super(message);
	}
}
