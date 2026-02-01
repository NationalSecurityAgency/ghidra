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
package ghidra.app.plugin.core.decompiler.taint.sarif;

import java.util.*;

import com.contrastsecurity.sarif.*;
import com.contrastsecurity.sarif.Result.Kind;
import com.contrastsecurity.sarif.Result.Level;

import ghidra.app.plugin.core.decompiler.taint.AbstractTaintState;
import ghidra.app.plugin.core.decompiler.taint.TaintRule;
import ghidra.program.model.address.Address;
import sarif.SarifUtils;
import sarif.handlers.SarifResultHandler;
import sarif.model.SarifDataFrame;

public class SarifTaintCodeFlowResultHandler extends SarifResultHandler {

	@Override
	public String getKey() {
		return "Address";
	}

	@Override
	public boolean isEnabled(SarifDataFrame dframe) {
		return dframe.getToolID().equals(AbstractTaintState.ENGINE_NAME);
	}

	@Override
	public void handle(SarifDataFrame dframe, Run r, Result res, Map<String, Object> map) {
		this.df = dframe;
		this.controller = df.getController();

		this.run = r;
		this.result = res;

		List<Map<String, Object>> tableResults = df.getTableResults();
		String ruleId = result.getRuleId();
		if (ruleId == null || !ruleId.equals("C0001")) {
			return;
		}
		String type = TaintRule.fromRuleId(ruleId).toString();
		// TODO: this is a bit weak
		String label = "UNSPECIFIED";
		Message msg = result.getMessage();
		String[] parts = msg.getText().split(":");
		if (parts.length > 1) {
			label = parts[1].strip();
		}
		String comment = result.getMessage().getText();

		List<CodeFlow> codeFlows = result.getCodeFlows();
		if (codeFlows == null) {
			return;
		}
		int path_id = 1;
		int path_index = 0;
		for (CodeFlow cf : codeFlows) {
			List<ThreadFlow> threadFlows = cf.getThreadFlows();
			if (threadFlows == null) {
				continue;
			}
			for (ThreadFlow tf : threadFlows) {
				List<ThreadFlowLocation> threadFlowLocations = tf.getLocations();
				path_index = 1;
				for (ThreadFlowLocation tfl : threadFlowLocations) {
					map.put("Message", result.getMessage().getText());
					Kind kind = result.getKind();
					map.put("Kind", kind == null ? "None" : kind.toString());
					Level level = result.getLevel();
					if (level != null) {
						map.put("Level", level.toString());
					}
					map.put("RuleId", result.getRuleId());
					map.put("type", type);
					map.put("value", label);
					map.put("comment", comment);
					map.put("pathID", path_id);
					map.put("index", path_index);
					populate(map, tfl, path_index);
					if (path_index > 1) {
						tableResults.add(map);
					}
					map = new HashMap<>();
					path_index++;
				}
			}
			path_id++;
		}
	}

	@Override
	protected Object parse() {
		// UNUSED
		return null;
	}

	private void populate(Map<String, Object> map, ThreadFlowLocation tfl, int path_index) {
		// For Source-Sink, these are the nodes. First is the Source, last is the Sink.
		Location loc = tfl.getLocation();
		LogicalLocation ll = SarifUtils.getLogicalLocation(run, loc);
		String name = ll.getName();
		String fqname = ll.getDecoratedName();
		String displayName = SarifUtils.extractDisplayName(ll);
		map.put("originalName", name);
		map.put("name", displayName);
		map.put("location", fqname);
		map.put("function", SarifUtils.extractFQNameFunction(fqname));

		Address faddr = SarifUtils.extractFunctionEntryAddr(controller.getProgram(), fqname);
		if (faddr != null && faddr.getOffset() >= 0) {
			map.put("entry", faddr);
			map.put("Address", faddr);
		}

		String kind = ll.getKind();
		String operation = "";

		switch (kind) {
			case "variable":
				map.put("Address",
					SarifUtils.extractFQNameAddrPair(controller.getProgram(), fqname).get(1));
				kind = path_index == 1 ? "path source" : "path sink";
				operation = path_index == 1 ? "Source" : "Sink";
				break;

			case "member":
				// instruction address.
				map.put("Address",
					SarifUtils.extractFQNameAddrPair(controller.getProgram(), fqname).get(1));
				operation = controller.getStateText(tfl.getState(), "assignment");
				kind = "path node";
				break;

			default:
				System.err.println(String.format("Path Kind: '%s' is unknown", kind));
		}
		map.put("kind", kind);
		map.put("operation", operation);
	}

}
