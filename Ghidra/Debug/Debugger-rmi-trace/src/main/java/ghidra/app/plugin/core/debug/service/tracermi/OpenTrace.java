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
package ghidra.app.plugin.core.debug.service.tracermi;

import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiHandler.*;
import ghidra.debug.api.tracermi.TraceRmiError;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.model.TransactionListener;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.Msg;

class OpenTrace implements ValueDecoder {
	final DoId doId;
	final Trace trace;
	final TraceRmiTarget target;
	final CurrentTxListener txListener;
	TraceSnapshot lastSnapshot;

	class CurrentTxListener implements TransactionListener {
		boolean undoable;

		public void markNotUndoable() {
			undoable = false;
		}

		@Override
		public void transactionStarted(DomainObjectAdapterDB domainObj, TransactionInfo tx) {
			undoable = true;
		}

		@Override
		public void transactionEnded(DomainObjectAdapterDB domainObj) {
			if (!undoable) {
				trace.clearUndo();
			}
		}

		@Override
		public void undoStackChanged(DomainObjectAdapterDB domainObj) {
			// NOP
		}

		@Override
		public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
			// NOP
		}
	}

	OpenTrace(DoId doId, Trace trace, TraceRmiTarget target) {
		this.doId = doId;
		this.trace = trace;
		this.target = target;
		this.txListener = new CurrentTxListener();

		trace.addTransactionListener(txListener);
	}

	public void dispose(TraceRmiHandler consumer) {
		trace.removeTransactionListener(txListener);
		trace.release(consumer);
	}

	public TraceSnapshot createSnapshot(long snap) {
		TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap, true);
		return this.lastSnapshot = snapshot;
	}

	public TraceSnapshot createSnapshot(TraceSchedule schedule) {
		if (schedule.isSnapOnly()) {
			return createSnapshot(schedule.getSnap());
		}
		TraceSnapshot snapshot = trace.getTimeManager().findScratchSnapshot(schedule);
		return this.lastSnapshot = snapshot;
	}

	public TraceObject getObject(long id, boolean required) {
		TraceObject object = trace.getObjectManager().getObjectById(id);
		if (object == null) {
			throw new InvalidObjIdError();
		}
		return object;
	}

	public TraceObject getObject(ObjPath path, boolean required) {
		TraceObject object =
			trace.getObjectManager().getObjectByCanonicalPath(TraceRmiHandler.toKeyPath(path));
		if (required && object == null) {
			throw new InvalidObjPathError(path.getPath());
		}
		return object;
	}

	@Override
	public TraceObject getObject(ObjDesc desc, boolean required) {
		return getObject(desc.getId(), required);
	}

	@Override
	public TraceObject getObject(ObjSpec object, boolean required) {
		return switch (object.getKeyCase()) {
			case KEY_NOT_SET -> throw new TraceRmiError("Must set id or path");
			case ID -> getObject(object.getId(), required);
			case PATH -> getObject(object.getPath(), required);
			default -> throw new AssertionError();
		};
	}

	public AddressSpace getSpace(String name, boolean required) {
		AddressSpace space = trace.getBaseAddressFactory().getAddressSpace(name);
		if (required && space == null) {
			throw new NoSuchAddressSpaceError(name);
		}
		return space;
	}

	@Override
	public Address toAddress(Addr addr, boolean required) {
		/**
		 * Do not clamp here, like we do for ranges. The purpose of the given address is more
		 * specific here. Plus, we're not just omitting some addresses (like we would for ranges),
		 * we'd be moving the address. Thus, we'd be applying some attribute to a location that was
		 * never intended.
		 */
		AddressSpace space = getSpace(addr.getSpace(), required);
		return space.getAddress(addr.getOffset());
	}

	@Override
	public AddressRange toRange(AddrRange range, boolean required) {
		AddressSpace space = getSpace(range.getSpace(), required);
		if (space == null) {
			return null;
		}
		/**
		 * Clamp to only the valid addresses, but do at least warn.
		 */
		long minOffset = range.getOffset();
		if (Long.compareUnsigned(minOffset, space.getMinAddress().getOffset()) < 0) {
			Msg.warn(this, "Range [%s:%x+%x] partially exceeds space min. Clamping."
					.formatted(range.getSpace(), range.getOffset(), range.getExtend()));
			minOffset = space.getMinAddress().getOffset();
		}
		else if (Long.compareUnsigned(minOffset, space.getMaxAddress().getOffset()) > 0) {
			throw new AddressOutOfBoundsException("Range [%s:%x+%x] entirely exceeds space max"
					.formatted(range.getSpace(), range.getOffset(), range.getExtend()));
		}
		long maxOffset = range.getOffset() + range.getExtend(); // Use the requested offset, not adjusted
		if (Long.compareUnsigned(maxOffset, space.getMaxAddress().getOffset()) > 0) {
			Msg.warn(this, "Range [%s:%x+%x] partially exceeds space max. Clamping."
					.formatted(range.getSpace(), range.getOffset(), range.getExtend()));
			maxOffset = space.getMaxAddress().getOffset();
		}
		else if (Long.compareUnsigned(maxOffset, space.getMinAddress().getOffset()) < 0) {
			throw new AddressOutOfBoundsException("Range [%s:%x+%x] entirely exceeds space min"
					.formatted(range.getSpace(), range.getOffset(), range.getExtend()));
		}
		Address min = space.getAddress(minOffset);
		Address max = space.getAddress(maxOffset);
		return new AddressRangeImpl(min, max);
	}

	public Register getRegister(String name, boolean required) {
		Register register = trace.getBaseLanguage().getRegister(name);
		if (required && register == null) {
			throw new InvalidRegisterError(name);
		}
		return register;
	}
}
