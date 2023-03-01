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

import java.util.*;

import org.apache.commons.collections4.IteratorUtils;

import ghidra.program.model.address.*;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.trace.database.symbol.DBTraceEquate;
import ghidra.trace.database.symbol.DBTraceEquateManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.listing.TraceCodeUnit;
import ghidra.util.IntersectionAddressSetView;
import ghidra.util.LockHold;
import ghidra.util.datastruct.WeakValueHashMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewEquateTable implements EquateTable {
	protected final DBTraceProgramView program;
	protected final DBTraceEquateManager equateManager;

	protected final Map<DBTraceEquate, DBTraceProgramViewEquate> cache = new WeakValueHashMap<>();

	public DBTraceProgramViewEquateTable(DBTraceProgramView program) {
		this.program = program;
		this.equateManager = program.trace.getEquateManager();
	}

	@Override
	public Equate createEquate(String name, long value)
			throws DuplicateNameException, InvalidInputException {
		try (LockHold hold = program.trace.lockWrite()) {
			DBTraceEquate equate = equateManager.create(name, value);
			DBTraceProgramViewEquate view = new DBTraceProgramViewEquate(program, equate);
			cache.put(equate, view);
			return view;
		}
	}

	@Override
	public boolean removeEquate(String name) {
		try (LockHold hold = program.trace.lockWrite()) {
			DBTraceEquate equate = equateManager.getByName(name);
			if (equate == null) {
				return false;
			}
			cache.remove(equate);
			equate.delete();
			return true;
		}
		// TODO: Listen for deletions of equates out-of-band
	}

	@Override
	public void deleteAddressRange(Address start, Address end, TaskMonitor monitor)
			throws CancelledException {
		equateManager.clearReferences(Lifespan.nowOn(program.snap),
			new AddressRangeImpl(start, end),
			monitor);
	}

	protected DBTraceProgramViewEquate doGetViewEquate(DBTraceEquate equate) {
		if (equate == null) {
			return null;
		}
		return cache.computeIfAbsent(equate, e -> new DBTraceProgramViewEquate(program, e));
	}

	@Override
	public Equate getEquate(String name) {
		try (LockHold hold = program.trace.lockRead()) {
			return doGetViewEquate(equateManager.getByName(name));
		}
	}

	@Override
	public Equate getEquate(Address reference, int opndPosition, long value) {
		try (LockHold hold = program.trace.lockRead()) {
			TraceCodeUnit cu = program.getTopCode(reference,
				(space, s) -> space.definedUnits().getContaining(s, reference));
			if (cu == null) {
				return null;
			}
			return doGetViewEquate(equateManager.getReferencedByValue(cu.getStartSnap(), reference,
				opndPosition, value));
		}
	}

	@Override
	public List<Equate> getEquates(Address reference, int opndPosition) {
		try (LockHold hold = program.trace.lockRead()) {
			List<Equate> result = new ArrayList<>();
			TraceCodeUnit cu = program.getTopCode(reference,
				(space, s) -> space.definedUnits().getContaining(s, reference));
			if (cu == null) {
				return result;
			}
			for (DBTraceEquate equate : equateManager.getReferenced(cu.getStartSnap(), reference,
				opndPosition)) {
				result.add(doGetViewEquate(equate));
			}
			return result;
		}
	}

	@Override
	public List<Equate> getEquates(Address reference) {
		try (LockHold hold = program.trace.lockRead()) {
			List<Equate> result = new ArrayList<>();
			TraceCodeUnit cu = program.getTopCode(reference,
				(space, s) -> space.definedUnits().getContaining(s, reference));
			if (cu == null) {
				return result;
			}
			for (DBTraceEquate equate : equateManager.getReferenced(cu.getStartSnap(), reference)) {
				result.add(doGetViewEquate(equate));
			}
			return result;
		}
	}

	@Override
	public AddressIterator getEquateAddresses() {
		return program.viewport
				.unionedAddresses(s -> equateManager.getReferringAddresses(Lifespan.at(s)))
				.getAddresses(true);
	}

	@Override
	public List<Equate> getEquates(long value) {
		try (LockHold hold = program.trace.lockRead()) {
			List<Equate> result = new ArrayList<>();
			for (DBTraceEquate equate : equateManager.getByValue(value)) {
				result.add(doGetViewEquate(equate));
			}
			return result;
		}
	}

	@Override
	public Iterator<Equate> getEquates() {
		return IteratorUtils.transformedIterator(equateManager.getAll().iterator(),
			e -> doGetViewEquate(e));
	}

	@Override
	public AddressIterator getEquateAddresses(Address start) {
		return program.viewport
				.unionedAddresses(s -> equateManager.getReferringAddresses(Lifespan.at(s)))
				.getAddresses(start, true);
	}

	@Override
	public AddressIterator getEquateAddresses(AddressSetView asv) {
		return new IntersectionAddressSetView(asv, program.viewport
				.unionedAddresses(s -> equateManager.getReferringAddresses(Lifespan.at(s))))
						.getAddresses(true);
	}
}
