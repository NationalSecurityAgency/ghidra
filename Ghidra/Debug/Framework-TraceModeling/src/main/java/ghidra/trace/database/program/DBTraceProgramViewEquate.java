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
package ghidra.trace.database.program;

import java.util.Collection;
import java.util.List;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Enum;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.trace.database.symbol.DBTraceEquate;
import ghidra.trace.model.symbol.TraceEquateReference;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class DBTraceProgramViewEquate implements Equate {
	protected final DBTraceProgramView program;
	protected final DBTraceEquate equate;

	public DBTraceProgramViewEquate(DBTraceProgramView program, DBTraceEquate equate) {
		this.program = program;
		this.equate = equate;
	}

	@Override
	public String getName() {
		return equate.getName();
	}

	@Override
	public String getDisplayName() {
		return equate.getDisplayName();
	}

	@Override
	public long getValue() {
		return equate.getValue();
	}

	@Override
	public String getDisplayValue() {
		return equate.getDisplayValue();
	}

	@Override
	public int getReferenceCount() {
		return equate.getReferenceCount();
	}

	@Override
	public void addReference(Address refAddr, int opndPosition) {
		equate.addReference(Range.atLeast(program.snap), null, refAddr, opndPosition);
	}

	@Override
	public void addReference(long dynamicHash, Address refAddr) {
		throw new UnsupportedOperationException(); // TODO
		//equate.addReference(Range.atLeast(program.snap), null, refAddr, )
	}

	@Override
	public void renameEquate(String newName) throws DuplicateNameException, InvalidInputException {
		equate.setName(newName);
	}

	@Override
	public EquateReference[] getReferences() {
		Collection<? extends TraceEquateReference> refs = equate.getReferences();
		return refs.toArray(new EquateReference[refs.size()]);
	}

	@Override
	public List<EquateReference> getReferences(Address refAddr) {
		return equate.getReferences(refAddr);
	}

	@Override
	public void removeReference(Address refAddr, int opndPosition) {
		TraceEquateReference ref = equate.getReference(program.snap, null, refAddr, opndPosition);
		if (ref == null) {
			return;
		}
		ref.delete();
	}

	@Override
	public void removeReference(long dynamicHash, Address refAddr) {
		throw new UnsupportedOperationException(); // TODO
		//equate.getReference(snap, thread, address, varnode)
	}

	@Override
	public boolean isValidUUID() {
		return equate.hasValidEnum();
	}

	@Override
	public boolean isEnumBased() {
		return equate.isEnumBased();
	}

	@Override
	public UniversalID getEnumUUID() {
		Enum dt = equate.getEnum();
		return dt == null ? null : dt.getUniversalID();
	}
}
