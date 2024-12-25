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

import java.util.*;

import com.contrastsecurity.sarif.*;

import db.Transaction;
import ghidra.program.model.address.Address;
import sarif.handlers.SarifResultHandler;
import sarif.model.SarifColumnKey;
import sarif.model.SarifDataFrame;

public class SarifPropertyResultHandler extends SarifResultHandler {

	@Override
	public String getKey() {
		return "Property";
	}

	@Override
	public List<Address> parse() {
		return controller.getListingAddresses(run, result);
	}

	@Override
	public void handle(SarifDataFrame dframe, Run run, Result result, Map<String, Object> map) {
		this.controller = dframe.getController();
		List<SarifColumnKey> columns = dframe.getColumns();
		List<String> columnNames = new ArrayList<>();
		for (SarifColumnKey c : columns) {
			columnNames.add(c.getName());
		}
		PropertyBag properties = result.getProperties();
		if (properties == null) {
			return;
		}
		Map<String, Object> additional = properties.getAdditionalProperties();
		if (additional == null) {
			return;
		}
		try (Transaction t = controller.getProgram().openTransaction("SARIF custom properties.")) {
			for (String key : additional.keySet()) {
				String[] splits = key.split("/");
				switch (splits[0]) {
					case "viewer":
						switch (splits[1]) {
							case "table":
								if (!columnNames.contains(splits[2])) {
									columns.add(new SarifColumnKey(splits[2], false));
								}
								map.put(splits[2], additional.get(key));
						}
						break;
					case "listing":
						controller.handleListingAction(run, result, splits[1], additional.get(key));
						break;
				}
			}
			t.commit();
		}
	}
}
