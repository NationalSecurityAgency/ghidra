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
package ghidra.program.model;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.FunctionSignature;

/**
 * A stub of the {@link FunctionSignature} interface.  This can be used to supply a test program 
 * manager or to spy on system internals by overriding methods as needed.
 */
public class TestDoubleFunctionSignature implements FunctionSignature {

	private String funtionSignature;
	private String name;

	public TestDoubleFunctionSignature(String prototypeString) {
		this.funtionSignature = prototypeString;
	}

	public TestDoubleFunctionSignature(String name, String prototypeString) {
		this.name = name;
		this.funtionSignature = prototypeString;
	}

	@Override
	public String getName() {
		if (name != null) {
			return name;
		}
		throw new UnsupportedOperationException();
	}

	@Override
	public ParameterDefinition[] getArguments() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getReturnType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getComment() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasVarArgs() {
		throw new UnsupportedOperationException();
	}

	@Override
	public GenericCallingConvention getGenericCallingConvention() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getPrototypeString() {
		return funtionSignature;
	}

	@Override
	public String getPrototypeString(boolean includeCallingConvention) {
		return funtionSignature;
	}

	@Override
	public boolean isEquivalentSignature(FunctionSignature signature) {
		throw new UnsupportedOperationException();
	}
}
