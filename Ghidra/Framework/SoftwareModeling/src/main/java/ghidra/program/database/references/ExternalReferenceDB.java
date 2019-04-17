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
package ghidra.program.database.references;

import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

class ExternalReferenceDB extends ReferenceDB implements ExternalReference {

	private Program program;

	public ExternalReferenceDB(Program program, Address fromAddr, Address toAddr, RefType refType,
			int opIndex, SourceType sourceType) {
		super(fromAddr, toAddr, refType, opIndex, sourceType, true, -1);
		this.program = program;
	}

	/**
	 * @see java.lang.Object#equals(Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof ExternalReference)) {
			return false;
		}
		Reference ref = (Reference) obj;
		if (fromAddr.equals(ref.getFromAddress()) && opIndex == ref.getOperandIndex() &&
			sourceType == ref.getSource() && refType == ref.getReferenceType()) {

			ExternalLocation externalLocation = getExternalLocation();
			if (externalLocation != null) {
				return externalLocation.isEquivalent(
					((ExternalReference) ref).getExternalLocation());
			}
		}
		return false;
	}

	@Override
	public String toString() {
		return "->" + getExternalLocation();
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isExternalReference()
	 */
	@Override
	public boolean isExternalReference() {
		return true;
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalReference#getExternalLocation()
	 */
	@Override
	public ExternalLocation getExternalLocation() {
		ExternalManagerDB extMgr = (ExternalManagerDB) program.getExternalManager();
		return extMgr.getExtLocation(toAddr);
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalReference#getLibraryName()
	 */
	@Override
	public String getLibraryName() {
		return getExternalLocation().getLibraryName();
	}

	/**
	 * @see ghidra.program.model.symbol.ExternalReference#getLabel()
	 */
	@Override
	public String getLabel() {
		return getExternalLocation().getLabel();
	}
}
