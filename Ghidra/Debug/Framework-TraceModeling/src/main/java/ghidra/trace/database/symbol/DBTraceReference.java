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
package ghidra.trace.database.symbol;

import java.util.Collection;
import java.util.Objects;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.symbol.DBTraceReferenceSpace.DBTraceReferenceEntry;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace.TraceReferenceChangeType;
import ghidra.trace.model.Trace.TraceSymbolChangeType;
import ghidra.trace.model.symbol.*;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;

public class DBTraceReference implements TraceReference {
	protected final DBTraceReferenceEntry ent;

	public DBTraceReference(DBTraceReferenceEntry ent) {
		this.ent = ent;
	}

	@Override
	public DBTrace getTrace() {
		return ent.space.trace;
	}

	public DBTraceThread getThread() {
		return ent.space.getThread();
	}

	@Override
	public void delete() {
		try (LockHold hold = LockHold.lock(ent.space.lock.writeLock())) {
			ent.doDelete();
			ent.space.trace.setChanged(
				new TraceChangeRecord<>(TraceReferenceChangeType.DELETED, ent.space, ent, this));
			if (isPrimary()) {
				Collection<? extends DBTraceReference> remaining = ent.space.getReferencesFrom(
					getStartSnap(), getFromAddress(), getOperandIndex());
				if (remaining.isEmpty()) {
					return;
				}
				DBTraceReference newPrimary = remaining.iterator().next();
				newPrimary.ent.setPrimary(true);
				ent.space.trace.setChanged(new TraceChangeRecord<>(
					TraceReferenceChangeType.PRIMARY_CHANGED, ent.space, this, false, true));
			}
		}
	}

	@Override
	public Range<Long> getLifespan() {
		return ent.getLifespan();
	}

	@Override
	public long getStartSnap() {
		return DBTraceUtils.lowerEndpoint(getLifespan());
	}

	@Override
	public Address getFromAddress() {
		return ent.getX1();
	}

	@Override
	public Address getToAddress() {
		return ent.toAddress;
	}

	@Override
	public void setPrimary(boolean primary) {
		// TODO: With time, this is actually much more complicated....
		// I may need another map/table altogether
		try (LockHold hold = LockHold.lock(ent.space.lock.writeLock())) {
			if (primary == isPrimary()) {
				return;
			}
			DBTraceReference oldPrimary = ent.space.getPrimaryReferenceFrom(getStartSnap(),
				getFromAddress(), getOperandIndex());
			if (oldPrimary != null) {
				oldPrimary.ent.setPrimary(false);
				ent.space.trace.setChanged(
					new TraceChangeRecord<>(TraceReferenceChangeType.PRIMARY_CHANGED, ent.space,
						oldPrimary, true, false));
			}
			ent.setPrimary(true);
			ent.space.trace.setChanged(new TraceChangeRecord<>(
				TraceReferenceChangeType.PRIMARY_CHANGED, ent.space, this, false, true));
		}
	}

	@Override
	public boolean isPrimary() {
		return ent.isPrimary();
	}

	@Override
	public long getSymbolID() {
		return ent.symbolId;
	}

	@Override
	public RefType getReferenceType() {
		return ent.refType;
	}

	@Override
	public int getOperandIndex() {
		return ent.opIndex;
	}

	@Override
	public SourceType getSource() {
		return ent.getSourceType();
	}

	@Override
	public void setReferenceType(RefType refType) {
		if (refType == RefType.EXTERNAL_REF) {
			throw new IllegalArgumentException("Trace does not allow external references");
		}
		try (LockHold hold = LockHold.lock(ent.space.lock.writeLock())) {
			ent.setRefType(refType);
		}
	}

	@Override
	public void setAssociatedSymbol(Symbol symbol) {
		try (LockHold hold = LockHold.lock(ent.space.lock.writeLock())) {
			AbstractDBTraceSymbol dbSym = getTrace().getSymbolManager().assertIsMine(symbol);
			if (ent.symbolId == symbol.getID()) {
				return;
			}
			Address toAddress = getToAddress();
			if (dbSym instanceof AbstractDBTraceVariableSymbol) {
				AbstractDBTraceVariableSymbol varSym = (AbstractDBTraceVariableSymbol) dbSym;
				// Variables' lifespans are governed by the parent function.
				// Globals span all time.
				DBTraceNamespaceSymbol parent = varSym.getParentNamespace();
				if (parent instanceof TraceSymbolWithLifespan) {
					TraceSymbolWithLifespan symWl = (TraceSymbolWithLifespan) parent;
					if (!symWl.getLifespan().isConnected(getLifespan())) {
						throw new IllegalArgumentException(
							"Associated symbol and reference must have connected lifespans");
					}
				}
				if (!varSym.getVariableStorage().contains(toAddress)) {
					throw new IllegalArgumentException(String.format(
						"Variable symbol storage of '%s' must contain Reference's to address (%s)",
						varSym.getName(), toAddress));
				}
			}
			else if (!Objects.equals(symbol.getAddress(), toAddress)) {
				throw new IllegalArgumentException(String.format(
					"Symbol address (%s) of '%s' must match Reference's to address (%s)",
					symbol.getAddress(), symbol.getName(), toAddress));
			}
			if (symbol instanceof TraceSymbolWithLifespan) {
				TraceSymbolWithLifespan symWl = (TraceSymbolWithLifespan) symbol;
				if (!symWl.getLifespan().isConnected(getLifespan())) {
					throw new IllegalArgumentException(
						"Associated symbol and reference must have connected lifespans");
				}
			}
			ent.setSymbolId(symbol.getID());
			getTrace().setChanged(new TraceChangeRecord<>(TraceSymbolChangeType.ASSOCIATION_ADDED,
				ent.space, dbSym, null, this));
		}
	}

	@Override
	public void clearAssociatedSymbol() {
		try (LockHold hold = LockHold.lock(ent.space.lock.writeLock())) {
			if (ent.symbolId == -1) {
				return;
			}
			TraceSymbol oldSymbol = getTrace().getSymbolManager().getSymbolByID(ent.symbolId);
			ent.setSymbolId(-1);
			getTrace().setChanged(new TraceChangeRecord<>(TraceSymbolChangeType.ASSOCIATION_REMOVED,
				ent.space, oldSymbol, this, null));
		}
	}

	@Override
	public int hashCode() {
		// Mimic the behavior of ReferenceDB 
		return ent.getX1().hashCode();
	}
}
