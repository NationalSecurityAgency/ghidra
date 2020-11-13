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
package ghidra.program.model.listing;

import ghidra.program.model.data.FunctionDefinitionDataType;

/**
 * Implementation of a Function Signature.  All the information about
 * a function that is portable from one program to another.
 *
 * @deprecated FunctionDefinitionDataType should be used for defining a function signature
 */
@Deprecated
public class FunctionSignatureImpl extends FunctionDefinitionDataType {

	/**
	 * Creates new FunctionSignatureImpl with the given name, default return type
	 * and no parameters.
	 * @param name the name of the function
	 */
	public FunctionSignatureImpl(String name) {
		super(name);
	}

	/**
	 * Creates new FunctionSignatureImpl based upon an existing function signature.
	 * @param signature the signature of the function
	 */
	public FunctionSignatureImpl(FunctionSignature signature) {
		super(signature);
	}

	/**
	 * Create a Function Definition based on a Function.
	 * The effective signature will be used where forced indirect and auto-params
	 * are reflected in the signature.
	 * @param function the function to use to create a Function Signature.
	 */
	public FunctionSignatureImpl(Function function) {
		super(function, false);
	}

	/**
	 * Create a Function Definition based on a Function
	 * @param function the function to use to create a Function Signature.
	 * @param formalSignature if true only original raw types will be retained and 
	 * auto-params discarded (e.g., this, __return_storage_ptr__, etc.).  If false,
	 * the effective signature will be used where forced indirect and auto-params
	 * are reflected in the signature.  This option has no affect if the specified 
	 * function has custom storage enabled.
	 */
	public FunctionSignatureImpl(Function function, boolean formalSignature) {
		super(function, formalSignature);
	}

}
