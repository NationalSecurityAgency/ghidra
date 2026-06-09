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
package ghidra.trace.database.memory;

import java.math.BigInteger;

import ghidra.pcode.utils.Utils;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.memory.TraceRegister;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;

public class DBTraceObjectRegister implements TraceRegister, DBTraceObjectInterface {
	private final DBTraceObject object;

	public DBTraceObjectRegister(DBTraceObject object) {
		this.object = object;
	}

	@Override
	public TraceObject getObject() {
		return object;
	}

	@Override
	public TraceThread getThread() {
		return object.queryCanonicalAncestorsInterface(TraceThread.class)
				.findAny()
				.orElseThrow();
	}

	@Override
	public String getName() {
		KeyPath path = object.getCanonicalPath();
		return KeyPath.parseIfIndex(path.key());
	}

	@Override
	public int getBitLength(long snap) {
		return TraceObjectInterfaceUtils.getValue(object, snap, TraceRegister.KEY_BITLENGTH,
			Integer.class, 0);
	}

	@Override
	public void setValue(Lifespan lifespan, byte[] value) {
		int length = getByteLength(lifespan.lmin());
		if (length != 0 && value.length != length) {
			throw new IllegalArgumentException("Length must match the register");
		}
		object.setValue(lifespan, TraceRegister.KEY_VALUE, value);
	}

	@Override
	public byte[] getValue(long snap) {
		TraceObjectValue ov = object.getValue(snap, TraceRegister.KEY_VALUE);
		if (ov == null) {
			return null;
		}
		Object val = ov.getValue();
		if (val instanceof byte[] arr) {
			// TODO: Should I correct mismatched size?
			return arr;
		}
		if (val instanceof String str) {
			// Always base 16. Model API says byte array for register value is big endian.
			BigInteger bigVal = new BigInteger(str, 16);
			return Utils.bigIntegerToBytes(bigVal, getByteLength(snap), true);
		}
		throw new ClassCastException("Cannot convert " + val + " to byte array for register value");
	}

	@Override
	public void setState(Lifespan lifespan, TraceMemoryState state) {
		// NB. There's no model equivalent, so encode using ordinal
		object.setValue(lifespan, KEY_STATE, state.ordinal());
	}

	@Override
	public TraceMemoryState getState(long snap) {
		return TraceMemoryState.values()[TraceObjectInterfaceUtils.getValue(object, snap, KEY_STATE,
			Integer.class, TraceMemoryState.UNKNOWN.ordinal())];
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		// TODO: Once we decide how to map registers....
		return null;
	}
}
