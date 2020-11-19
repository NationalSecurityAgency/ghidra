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
package ghidra.app.plugin.core.string.variadic;

import ghidra.program.model.address.*;

/**
 * Class for encapsulating a variadic function call
 */
public class FunctionCallData {

	private Address addressOfCall;
	private String callFunctionName;
	private String formatString;

	/**
	 * Constructore for FuncCallData
	 * 
	 * @param addressOfCall   Address of function call
	 * @param callFunctionName variadic function name
	 * @param formatString       format String
	 */
	public FunctionCallData(Address addressOfCall, String callFunctionName, String formatString) {
		this.addressOfCall = addressOfCall;
		this.callFunctionName = callFunctionName;
		this.formatString = formatString;
	}

	/**
	 * addressOfCall getter
	 * 
	 * @return addressOfCall
	 */
	public Address getAddressOfCall() {
		return this.addressOfCall;
	}

	/**
	 * callFunctionName getter
	 * 
	 * @return callFunctionName
	 */
	public String getCallFuncName() {
		return this.callFunctionName;
	}

	/**
	 * formatString getter
	 * 
	 * @return formatString
	 */
	public String getFormatString() {
		return this.formatString;
	}
}
