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
package ghidra.util.exception;

import java.io.IOException;

/**
 * <code>ClosedException</code> indicates that the underlying resource has been 
 * closed and read/write operations have failed.
 */
public class ClosedException extends IOException {
	
	private String resourceName;
	
	/**
	 * Default constructor.  Message indicates 'File is closed'.
	 */
	public ClosedException() {
		super("File is closed");
	}
	
	/**
	 * Constructor which indicates resource which has been closed.
	 * Message indicates '&lt;resourceName&gt; is closed'.
	 * @param resourceName name of closed resource.
	 */
	public ClosedException(String resourceName) {
		super(resourceName + " is closed");
		this.resourceName = resourceName;
	}
	
	/**
	 * @return name of resource which is closed.
	 */
	public String getResourceName() {
		return resourceName;
	}
	

}
