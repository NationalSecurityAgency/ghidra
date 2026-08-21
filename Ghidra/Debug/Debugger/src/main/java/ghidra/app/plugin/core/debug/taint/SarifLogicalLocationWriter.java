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
package ghidra.app.plugin.core.debug.taint;

import java.io.IOException;
import java.util.Map.Entry;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.*;

public class SarifLogicalLocationWriter extends AbstractExtWriter {

	private WrappedLogicalLocation lloc;
	private String key;
	private String type;
	private String value;
	private Address addr;

	public SarifLogicalLocationWriter(Entry<TraceAddressSnapRange, String> entry,
			FunctionManager fmgr)
			throws IOException {
		super(null);

		Function f = null;
		String location = "UNKNOWN";
		Address min = entry.getKey().getX1();
		key = min.toString(true);
		type = min.getAddressSpace().getName();
		value = entry.getValue();

		if (value.contains("@")) {
			String[] split = value.split("@");
			value = split[0];
			String[] vSplit = split[1].split(",");
			try {
				String seq = vSplit[1].substring(3).trim() + ":" + vSplit[2].trim();
				addr = min.getAddress(vSplit[1].trim());
				f = fmgr.getFunctionContaining(addr);
				if (f != null) {
					location = f.getName() + ":" + key;
					location += "@" + f.getEntryPoint();
					location += ":" + seq;
				}
			}
			catch (AddressFormatException e) {
				e.printStackTrace();
			}
		}
		ExtLogicalLocation ext = new ExtLogicalLocation(key, f, location, "");
		lloc = new WrappedLogicalLocation(ext, addr);
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genData(monitor);
		root.add("logicalLocation", objects);
	}

	private void genData(TaskMonitor monitor) {
		objects.add(getTree(lloc.getLogicalLocation()));
	}

	public WrappedLogicalLocation getLogicalLocation() {
		return lloc;
	}

	public Address getAddress() {
		return addr;
	}

	public String getKey() {
		return key;
	}

	public String getValue() {
		return value;
	}

	public String getType() {
		return type;
	}

}
