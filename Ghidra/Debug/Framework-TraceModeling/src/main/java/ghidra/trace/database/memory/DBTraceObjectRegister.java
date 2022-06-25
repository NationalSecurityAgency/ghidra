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

import com.google.common.collect.Range;

import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.util.PathUtils;
import ghidra.pcode.utils.Utils;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.memory.TraceObjectRegister;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.util.TraceChangeRecord;

public class DBTraceObjectRegister implements TraceObjectRegister, DBTraceObjectInterface {
	private final DBTraceObject object;

	public DBTraceObjectRegister(DBTraceObject object) {
		this.object = object;
	}

	@Override
	public TraceObject getObject() {
		return object;
	}

	@Override
	public TraceObjectThread getThread() {
		return object.queryCanonicalAncestorsInterface(TraceObjectThread.class)
				.findAny()
				.orElseThrow();
	}

	@Override
	public String getName() {
		TraceObjectKeyPath path = object.getCanonicalPath();
		if (PathUtils.isIndex(path.key())) {
			return path.index();
		}
		return path.key();
	}

	@Override
	public int getLength() {
		return TraceObjectInterfaceUtils.getValue(object, computeMinSnap(),
			TargetRegister.LENGTH_ATTRIBUTE_NAME, Integer.class, 0);
	}

	@Override
	public void setValue(Range<Long> lifespan, byte[] value) {
		int length = getLength();
		if (length != 0 && value.length != length) {
			throw new IllegalArgumentException("Length must match the register");
		}
		object.setValue(lifespan, TargetRegister.VALUE_ATTRIBUTE_NAME, value);
	}

	@Override
	public byte[] getValue(long snap) {
		TraceObjectValue ov = object.getValue(snap, TargetRegister.VALUE_ATTRIBUTE_NAME);
		if (ov == null) {
			return null;
		}
		Object val = ov.getValue();
		if (val instanceof byte[]) {
			// TODO: Should I correct mismatched size?
			return (byte[]) val;
		}
		if (val instanceof String) {
			// Always base 16. Model API says byte array for register value is big endian.
			BigInteger bigVal = new BigInteger((String) val, 16);
			return Utils.bigIntegerToBytes(bigVal, getLength(), true);
		}
		throw new ClassCastException("Cannot convert " + val + " to byte array for register value");
	}

	@Override
	public void setState(Range<Long> lifespan, TraceMemoryState state) {
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
