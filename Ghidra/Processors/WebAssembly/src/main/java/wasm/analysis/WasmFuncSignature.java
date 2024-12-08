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
package wasm.analysis;

import ghidra.program.model.address.Address;
import wasm.format.WasmEnums.ValType;

public class WasmFuncSignature {
	private ValType[] params;
	private ValType[] returns;
	private int funcIdx;
	private String name;
	private Address startAddr;
	private Address endAddr; // address of last byte in the function (inclusive)
	private ValType[] locals;

	public ValType[] getParams() {
		return params;
	}

	public ValType[] getReturns() {
		return returns;
	}

	public ValType[] getLocals() {
		return locals;
	}

	public int getFuncIdx() {
		return funcIdx;
	}

	public String getName() {
		return name;
	}

	public Address getStartAddr() {
		return startAddr;
	}

	public Address getEndAddr() {
		return endAddr;
	}

	public boolean isImport() {
		return locals == null;
	}

	public WasmFuncSignature(ValType[] paramTypes, ValType[] returnTypes, int funcIdx, String name, Address addr) {
		this.funcIdx = funcIdx;
		this.name = name;
		this.startAddr = addr;
		this.params = paramTypes;
		this.returns = returnTypes;
	}

	public WasmFuncSignature(ValType[] paramTypes, ValType[] returnTypes, int funcIdx, String name, Address startAddr, Address endAddr, ValType[] locals) {
		this(paramTypes, returnTypes, funcIdx, name, startAddr);
		this.endAddr = endAddr;
		this.locals = locals;
	}

	@Override
	public String toString() {
		return String.format("%s @ %s %dT -> %dT", name, startAddr.toString(), params.length, returns.length);
	}
}
