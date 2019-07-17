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

import java.util.*;

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.listing.*;
import ghidra.util.exception.AssertException;

public class MultipleParameterStringable extends Stringable {

	public static final String SHORT_NAME = "MULTI_PARAM";

	private static final String CUSTOM_DELIMITER = "\n";

	private List<ParameterStringable> parameterStringables = new ArrayList<ParameterStringable>();

	public MultipleParameterStringable() {
		this(null);
	}

	public MultipleParameterStringable(List<ParameterStringable> parameterStringables) {
		super(SHORT_NAME);
		this.parameterStringables = parameterStringables;
		if (parameterStringables == null) {
			this.parameterStringables = new ArrayList<ParameterStringable>();
		}
	}

	@Override
	protected String doConvertToString(Program program) {
		StringBuffer buffy = new StringBuffer();

		for (Stringable stringable : parameterStringables) {
			buffy.append(Stringable.getString(stringable, program)).append(CUSTOM_DELIMITER);
		}
		return buffy.toString();
	}

	@Override
	protected void doRestoreFromString(String string, Program program) {
		if (string == null) {
			return;
		}

		StringTokenizer tokenizer = new StringTokenizer(string, CUSTOM_DELIMITER);
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			Stringable stringable = Stringable.getStringable(token, program);
			if (!(stringable instanceof ParameterStringable)) {
				throw new AssertException("Coding Error: how can we get a stringable that "
					+ "is not the right type?");
			}

			parameterStringables.add((ParameterStringable) stringable);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = prime * ((parameterStringables == null) ? 0 : parameterStringables.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		
		if (this == obj) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		MultipleParameterStringable other = (MultipleParameterStringable) obj;
		if (parameterStringables == null) {
			if (other.parameterStringables != null) {
				return false;
			}
		}
		else if (!parameterStringables.equals(other.parameterStringables)) {
			return false;
		}
		return true;
	}

	@Override
	public String getDisplayString() {
		StringBuffer buffy = new StringBuffer();
		for (Stringable stringable : parameterStringables) {
			buffy.append(stringable.getDisplayString()).append('\n');
		}
		return buffy.toString();
	}

	public List<Parameter> getParameterDefinitions(Function destFunction) {
		List<Parameter> list = new ArrayList<Parameter>();
		int ordinal = 0;
		for (ParameterStringable stringable : parameterStringables) {
			list.add(stringable.getParameterDefinition(destFunction, ordinal++));
		}
		return list;
	}
}
