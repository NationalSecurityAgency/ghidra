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
package ghidra.lisa.pcode.contexts;

import ghidra.program.model.address.Address;

public class SymbolVarnodeContext extends VarnodeContext {

	private String context;
	private int size;

	/*
	 * This class is essentially a dummy context for the case where the varnode's id is a memory address
	 */
	public SymbolVarnodeContext(String name, Address context) {
		this(context);
		this.context = name;
	}

	public SymbolVarnodeContext(Address context) {
		super(null);
		this.context = context.toString();
		size = context.getPointerSize();
	}

	@Override
	public boolean isConstant() {
		return false;
	}

	@Override
	public int getSize() {
		return size;
	}

	@Override
	public long getOffset() {
		return 0;
	}

	@Override
	public String getText() {
		return context;
	}

}
