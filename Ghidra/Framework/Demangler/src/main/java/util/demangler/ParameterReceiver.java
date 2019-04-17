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
package util.demangler;

import java.util.List;

/**
 * A generic interface to represent
 * object that support parameters.
 */
public interface ParameterReceiver {
	/**
	 * Adds the specified parameter to this object.
	 * @param parameter the parameter to add
	 */
	public void addParameter(GenericDemangledDataType parameter);

	/**
	 * Returns the parameters added to this object.
	 * @return the parameters added to this object
	 */
	public List<GenericDemangledDataType> getParameters();
}
