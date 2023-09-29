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
package ghidra.app.plugin.core.debug.service.rmi.trace;

import ghidra.app.plugin.core.debug.service.rmi.trace.TraceRmiHandler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.time.TraceSnapshot;

class OpenTrace implements ValueDecoder {
	final DoId doId;
	final Trace trace;
	TraceSnapshot lastSnapshot;

	OpenTrace(DoId doId, Trace trace) {
		this.doId = doId;
		this.trace = trace;
	}

	public TraceSnapshot createSnapshot(Snap snap, String description) {
		TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap.getSnap(), true);
		snapshot.setDescription(description);
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
			throw new InvalidObjPathError();
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
			throw new NoSuchAddressSpaceError();
		}
		return space;
	}

	@Override
	public Address toAddress(Addr addr, boolean required) {
		AddressSpace space = getSpace(addr.getSpace(), required);
		return space.getAddress(addr.getOffset());
	}

	@Override
	public AddressRange toRange(AddrRange range, boolean required)
			throws AddressOverflowException {
		AddressSpace space = getSpace(range.getSpace(), required);
		if (space == null) {
			return null;
		}
		Address min = space.getAddress(range.getOffset());
		Address max = space.getAddress(range.getOffset() + range.getExtend());
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
