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
package agent.dbgeng.model.iface2;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.DbgModule;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.*;

public interface DbgModelTargetModule extends DbgModelTargetObject, TargetModule {

	DbgModule getDbgModule();

	@Override
	public default CompletableFuture<Void> init(Map<String, Object> map) {
		AddressSpace space = getModel().getAddressSpace("ram");
		return requestNativeAttributes().thenAccept(attrs -> {
			if (!isValid()) {
				return;
			}
			if (attrs != null) {
				map.putAll(attrs);
				TargetObject baseAttr = (TargetObject) attrs.get("BaseAddress");
				TargetObject nameAttr = (TargetObject) attrs.get("Name");
				TargetObject sizeAttr = (TargetObject) attrs.get("Size");

				Object baseval = baseAttr == null ? null
						: baseAttr.getCachedAttribute(VALUE_ATTRIBUTE_NAME);
				Object nameval = nameAttr == null ? null
						: nameAttr.getCachedAttribute(VALUE_ATTRIBUTE_NAME);
				Object sizeval = sizeAttr == null ? null
						: sizeAttr.getCachedAttribute(VALUE_ATTRIBUTE_NAME);

				String basestr = baseval == null ? "0" : baseval.toString();
				String namestr = nameval == null ? "" : nameval.toString();
				String sizestr = sizeval == null ? "1" : sizeval.toString();

				String shortnamestr = namestr;
				int sep = shortnamestr.lastIndexOf('\\');
				if (sep > 0 && sep < shortnamestr.length()) {
					shortnamestr = shortnamestr.substring(sep + 1);
				}
				Long base = Long.parseUnsignedLong(basestr, 16);
				Integer sz = Integer.parseInt(sizestr, 16);
				Address min = space.getAddress(base);
				Address max = min.add(sz - 1);
				AddressRange range = new AddressRangeImpl(min, max);
				map.put(RANGE_ATTRIBUTE_NAME, range);

				String oldval = (String) getCachedAttribute(DISPLAY_ATTRIBUTE_NAME);
				map.put(MODULE_NAME_ATTRIBUTE_NAME, namestr);
				map.put(SHORT_DISPLAY_ATTRIBUTE_NAME, shortnamestr);
				map.put(DISPLAY_ATTRIBUTE_NAME, shortnamestr);
				setModified(map, !shortnamestr.equals(oldval));
			}
		});
	}

}
