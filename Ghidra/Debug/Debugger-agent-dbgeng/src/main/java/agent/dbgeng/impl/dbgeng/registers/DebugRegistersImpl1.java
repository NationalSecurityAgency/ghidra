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
package agent.dbgeng.impl.dbgeng.registers;

import java.util.*;

import com.sun.jna.Native;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DbgEng.OpaqueCleanable;
import agent.dbgeng.dbgeng.DebugValue.DebugValueType;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_REGISTER_DESCRIPTION;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;
import agent.dbgeng.jna.dbgeng.registers.IDebugRegisters;
import ghidra.comm.util.BitmaskSet;

public class DebugRegistersImpl1 implements DebugRegistersInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugRegisters jnaRegisters;

	public DebugRegistersImpl1(IDebugRegisters jnaRegisters) {
		this.cleanable = DbgEng.releaseWhenPhantom(this, jnaRegisters);
		this.jnaRegisters = jnaRegisters;
	}

	@Override
	public int getNumberRegisters() {
		ULONGByReference pulNumber = new ULONGByReference();
		COMUtils.checkRC(jnaRegisters.GetNumberRegisters(pulNumber));
		return pulNumber.getValue().intValue();
	}

	@Override
	public DebugRegisterDescription getDescription(int registerIndex) {
		ULONG ulRegIdx = new ULONG(registerIndex);
		ULONGByReference pulNameSize = new ULONGByReference();
		COMUtils.checkRC(
			jnaRegisters.GetDescription(ulRegIdx, null, new ULONG(0), pulNameSize, null));
		byte[] name = new byte[pulNameSize.getValue().intValue()];
		DEBUG_REGISTER_DESCRIPTION.ByReference desc = new DEBUG_REGISTER_DESCRIPTION.ByReference();
		COMUtils.checkRC(
			jnaRegisters.GetDescription(ulRegIdx, name, pulNameSize.getValue(), null, desc));

		return new DebugRegisterDescription(Native.toString(name), registerIndex,
			DebugValueType.values()[desc.Type.intValue()],
			new BitmaskSet<>(DebugRegisterFlags.class, desc.Flags.intValue()),
			desc.SubregMaster.intValue(), desc.SubregLength.intValue(), desc.SubregMask.longValue(),
			desc.SubregShift.intValue());
	}

	@Override
	public int getIndexByName(String name) {
		ULONGByReference pulIndex = new ULONGByReference();
		HRESULT hr = jnaRegisters.GetIndexByName(name, pulIndex);
		if (hr.equals(COMUtilsExtra.E_NOINTERFACE)) {
			// This happens for 32-bit WOW execution
			return -1;
		}
		COMUtils.checkRC(hr);
		return pulIndex.getValue().intValue();
	}

	@Override
	public DebugValue getValue(int index) {
		ULONG ulIndex = new ULONG(index);
		DEBUG_VALUE.ByReference dvVal = new DEBUG_VALUE.ByReference();
		COMUtils.checkRC(jnaRegisters.GetValue(ulIndex, dvVal));
		return dvVal.convertTo(DebugValue.class);
	}

	protected void doGetValues(DebugRegisterSource source, ULONG ulCount, ULONG[] pulIndices,
			DEBUG_VALUE[] pValues) {
		if (source != DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE) {
			throw new IllegalArgumentException("This interface only permits DEBUG_REGSRC_DEBUGGEE");
		}
		COMUtils.checkRC(jnaRegisters.GetValues(ulCount, pulIndices, new ULONG(0), pValues));
	}

	@Override
	public Map<Integer, DebugValue> getValues(DebugRegisterSource source,
			Collection<Integer> indices) {
		if (source != DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE) {
			throw new IllegalArgumentException("This interface only permits DEBUG_REGSRC_DEBUGGEE");
		}
		if (indices.isEmpty()) {
			return Collections.emptyMap();
		}
		List<Integer> li = new ArrayList<>(indices);
		ULONG ulCount = new ULONG(li.size());
		ULONG[] pulIndices = new ULONG[li.size()];
		DEBUG_VALUE[] pValues = (DEBUG_VALUE[]) new DEBUG_VALUE().toArray(li.size());
		for (int i = 0; i < indices.size(); i++) {
			pulIndices[i] = new ULONG(li.get(i));
		}
		doGetValues(source, ulCount, pulIndices, pValues);
		Map<Integer, DebugValue> result = new LinkedHashMap<>();
		for (int i = 0; i < li.size(); i++) {
			result.put(li.get(i), pValues[i].convertTo(DebugValue.class));
		}
		return result;
	}

	@Override
	public void setValue(int index, DebugValue value) {
		ULONG ulIndex = new ULONG(index);
		DEBUG_VALUE.ByReference dvVal = new DEBUG_VALUE.ByReference();
		DEBUG_VALUE.fromDebugValue(dvVal, value);
		COMUtils.checkRC(jnaRegisters.SetValue(ulIndex, dvVal));
	}

	protected void doSetValues(DebugRegisterSource source, ULONG ulCount, ULONG[] pulIndices,
			DEBUG_VALUE[] pValues) {
		if (source != DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE) {
			throw new IllegalArgumentException("This interface only permits DEBUG_REGSRC_DEBUGGEE");
		}

		COMUtils.checkRC(jnaRegisters.SetValues(ulCount, pulIndices, new ULONG(0), pValues));
	}

	@Override
	public void setValues(DebugRegisterSource source, Map<Integer, DebugValue> values) {
		if (values.isEmpty()) {
			return;
		}
		ULONG ulCount = new ULONG(values.size());
		ULONG[] pulIndices = new ULONG[values.size()];
		DEBUG_VALUE[] pValues = (DEBUG_VALUE[]) new DEBUG_VALUE().toArray(values.size());
		int i = 0;
		for (Map.Entry<Integer, DebugValue> ent : values.entrySet()) {
			pulIndices[i] = new ULONG(ent.getKey());
			DEBUG_VALUE.fromDebugValue(pValues[i], ent.getValue());
			i++;
		}
		doSetValues(source, ulCount, pulIndices, pValues);
	}
}
