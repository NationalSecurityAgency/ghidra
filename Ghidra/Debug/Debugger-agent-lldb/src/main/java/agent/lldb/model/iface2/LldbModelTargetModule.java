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
package agent.lldb.model.iface2;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import SWIG.SBModule;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;

public interface LldbModelTargetModule extends LldbModelTargetObject, TargetModule {

	SBModule getModule();

	@Override
	public default CompletableFuture<Void> init(Map<String, Object> map) {
		AddressSpace space = getModel().getAddressSpace("ram");
		return requestNativeAttributes().thenAccept(attrs -> {
			if (attrs != null) {
				map.putAll(attrs);
				TargetObject baseOffset2 = (TargetObject) attrs.get("BaseAddress");
				TargetObject nameAttr = (TargetObject) attrs.get("Name");
				TargetObject size = (TargetObject) attrs.get("Size");
				String basestr = baseOffset2 == null ? "0"
						: baseOffset2.getCachedAttribute(VALUE_ATTRIBUTE_NAME).toString();
				String namestr = nameAttr == null ? ""
						: nameAttr.getCachedAttribute(VALUE_ATTRIBUTE_NAME).toString();
				String sizestr =
					size == null ? "1" : size.getCachedAttribute(VALUE_ATTRIBUTE_NAME).toString();
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

	void setRange(AddressRangeImpl addressRangeImpl);

}
