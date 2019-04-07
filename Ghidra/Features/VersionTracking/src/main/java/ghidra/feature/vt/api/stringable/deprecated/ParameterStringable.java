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
package ghidra.feature.vt.api.stringable.deprecated;

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.listing.*;

public class ParameterStringable extends Stringable {

	public static final String SHORT_NAME = "PARAM";

	private ParameterInfo parameterInfo;

	public ParameterStringable() {
		super(SHORT_NAME);
	}

	public ParameterStringable(Parameter parameter) {
		super(SHORT_NAME);
		parameterInfo = ParameterInfo.createParameterInfo(parameter);
	}

	public Parameter getParameterDefinition(Function destFunction, int ordinal) {
		return parameterInfo.createParameterDefinition(destFunction, ordinal);
	}

	@Override
	public String getDisplayString() {
		return parameterInfo.getDataType().getName() + " " + parameterInfo.getName();
	}

	@Override
	protected String doConvertToString(Program program) {
		return parameterInfo.convertToString();
	}

	@Override
	protected void doRestoreFromString(String string, Program program) {
		parameterInfo = ParameterInfo.createParameterInfo(string, program);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = prime * ((parameterInfo == null) ? 0 : parameterInfo.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		
		if (this == obj)
			return true;
		if (getClass() != obj.getClass())
			return false;
		ParameterStringable other = (ParameterStringable) obj;
		if (parameterInfo == null) {
			if (other.parameterInfo != null)
				return false;
		}
		else if (!parameterInfo.equals(other.parameterInfo))
			return false;
		return true;
	}

}
