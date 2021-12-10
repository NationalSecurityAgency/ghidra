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
package ghidra.trace.database.address;

import ghidra.program.database.ProgramAddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.util.exception.DuplicateNameException;

public class TraceAddressFactory extends ProgramAddressFactory {

	public TraceAddressFactory(Language language, CompilerSpec compilerSpec) {
		super(language, compilerSpec);
	}

	@Override // for peer access
	protected OverlayAddressSpace addOverlayAddressSpace(String name, boolean preserveName,
			AddressSpace originalSpace, long minOffset, long maxOffset) {
		return super.addOverlayAddressSpace(name, preserveName, originalSpace, minOffset,
			maxOffset);
	}

	@Override // for peer access
	protected void addOverlayAddressSpace(OverlayAddressSpace ovSpace)
			throws DuplicateNameException {
		super.addOverlayAddressSpace(ovSpace);
	}

	@Override // for peer access
	protected void removeOverlaySpace(String name) {
		super.removeOverlaySpace(name);
	}
}
