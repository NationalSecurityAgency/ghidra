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
package ghidra.program.model.data;

/**
 * <code>DataTypeDependencyException</code> corresponds to a datatype dependency failure.
 * This can occur under various situations, including when trying to replace a dataType 
 * with a dataType that depends on the dataType being replaced.  This error may also occur
 * when a datatype dependency can not be satisfied.
 */

public class DataTypeDependencyException extends Exception {

	public DataTypeDependencyException() {
		super();
	}

	public DataTypeDependencyException(String message) {
		super(message);
	}

	public DataTypeDependencyException(Throwable cause) {
		super(cause);
	}

	public DataTypeDependencyException(String message, Throwable cause) {
		super(message, cause);
	}

}
