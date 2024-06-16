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
package sarif.handlers.result;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.contrastsecurity.sarif.CodeFlow;
import com.contrastsecurity.sarif.ThreadFlow;
import com.contrastsecurity.sarif.ThreadFlowLocation;

import ghidra.program.model.address.Address;
import sarif.handlers.SarifResultHandler;

public class SarifCodeFlowResultHandler extends SarifResultHandler {

	public String getKey() {
		return "CodeFlows";
	}

	public List<Map<String, List<Address>>> parse() {
		List<Map<String, List<Address>>> res = new ArrayList<>();
		List<CodeFlow> codeFlows = result.getCodeFlows();
		if (codeFlows != null) {
			for (CodeFlow f : codeFlows) {
				Map<String, List<Address>> map = new HashMap<>();
				parseCodeFlow(f, map);
				res.add(map);
			}
		}
		return res;
	}

	private void parseCodeFlow(CodeFlow f, Map<String, List<Address>> map) {
		for (ThreadFlow t : f.getThreadFlows()) {
			List<Address> addrs = new ArrayList<Address>();
			for (ThreadFlowLocation loc : t.getLocations()) {
				addrs.add(controller.locationToAddress(loc.getLocation()));
			}
			map.put(t.getId(), addrs);
		}
	}

}
