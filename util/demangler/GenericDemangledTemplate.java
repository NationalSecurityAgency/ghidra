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

import java.util.ArrayList;
import java.util.List;

public class GenericDemangledTemplate implements ParameterReceiver {
	private List<GenericDemangledDataType> parameters = new ArrayList<GenericDemangledDataType>();

	public GenericDemangledTemplate() {
	}

	@Override
	public void addParameter(GenericDemangledDataType parameter) {
		parameters.add(parameter);
	}

	@Override
	public List<GenericDemangledDataType> getParameters() {
		return new ArrayList<GenericDemangledDataType>(parameters);
	}

	public String toTemplate() {
		StringBuffer buffer = new StringBuffer();
		buffer.append('<');
		for (int i = 0; i < parameters.size(); ++i) {
			buffer.append(parameters.get(i).toSignature());
			if (i < parameters.size() - 1) {
				buffer.append(',');
			}
		}
		buffer.append('>');
		return buffer.toString();
	}

	@Override
	public String toString() {
		return toTemplate();
	}
}
