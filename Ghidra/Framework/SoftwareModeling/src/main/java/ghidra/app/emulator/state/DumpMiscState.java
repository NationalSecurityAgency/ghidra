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
package ghidra.app.emulator.state;

import generic.stl.Pair;
import ghidra.program.model.lang.Language;
import ghidra.util.*;

import java.util.*;

public class DumpMiscState implements RegisterState {

	private Map<String, Pair<Boolean, byte[]>> context =
		new HashMap<String, Pair<Boolean, byte[]>>();

	private DataConverter dc;

	public DumpMiscState(Language lang) {
		dc =
			lang.isBigEndian() ? BigEndianDataConverter.INSTANCE
					: LittleEndianDataConverter.INSTANCE;
	}

	@Override
	public void dispose() {
		context.clear();
	}

	@Override
	public Set<String> getKeys() {
		return context.keySet();
	}

	@Override
	public List<byte[]> getVals(String key) {
		List<byte[]> list = new ArrayList<byte[]>();
		Pair<Boolean, byte[]> pair = context.get(key);
		if (pair != null && pair.second != null) {
			list.add(pair.second);
		}
		return list;
	}

	@Override
	public List<Boolean> isInitialized(String key) {
		List<Boolean> list = new ArrayList<Boolean>();
		Pair<Boolean, byte[]> pair = context.get(key);
		if (pair != null && pair.first != null) {
			list.add(pair.first);
		}
		else {
			list.add(Boolean.FALSE);
		}
		return list;
	}

	@Override
	public void setVals(String key, byte[] vals, boolean setInitiailized) {
		Pair<Boolean, byte[]> pair = new Pair<Boolean, byte[]>(setInitiailized, vals);
		context.put(key, pair);
	}

	@Override
	public void setVals(String key, long val, int size, boolean setInitiailized) {
		byte[] bytes = new byte[size];
		dc.getBytes(val, size, bytes, 0);
		setVals(key, bytes, setInitiailized);
	}

}
