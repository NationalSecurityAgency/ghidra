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

import ghidra.program.database.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.util.exception.DuplicateNameException;

public class TraceAddressFactory extends ProgramAddressFactory {

	public TraceAddressFactory(Language language, CompilerSpec compilerSpec,
			OverlayRegionSupplier overlayRegionSupplier) {
		super(language, compilerSpec, overlayRegionSupplier);
	}

	@Override
	protected boolean isValidOverlayBaseSpace(AddressSpace baseSpace) {
		return super.isValidOverlayBaseSpace(baseSpace) ||
			baseSpace.getType() == AddressSpace.TYPE_REGISTER;
	}

	@Override // for peer access
	protected ProgramOverlayAddressSpace addOverlaySpace(long key, String overlayName,
			AddressSpace baseSpace) throws DuplicateNameException {
		return super.addOverlaySpace(key, overlayName, baseSpace);
	}

	@Override // for peer access
	protected void addOverlaySpace(ProgramOverlayAddressSpace ovSpace)
			throws DuplicateNameException {
		super.addOverlaySpace(ovSpace);
	}

	@Override // for peer access
	protected void removeOverlaySpace(String name) {
		super.removeOverlaySpace(name);
	}

	@Override // for peer access
	protected void overlaySpaceRenamed(String oldOverlaySpaceName, String newName,
			boolean refreshStatusIfNeeded) {
		super.overlaySpaceRenamed(oldOverlaySpaceName, newName, refreshStatusIfNeeded);
	}

	@Override // for peer access
	protected void refreshStaleOverlayStatus() {
		super.refreshStaleOverlayStatus();
	}

}
