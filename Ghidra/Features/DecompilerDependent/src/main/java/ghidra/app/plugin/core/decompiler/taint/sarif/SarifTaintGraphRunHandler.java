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

import java.util.Map;
import java.util.Map.Entry;

import com.contrastsecurity.sarif.*;

import ghidra.app.plugin.core.decompiler.taint.TaintService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.service.graph.AttributedVertex;
import sarif.SarifUtils;
import sarif.handlers.run.SarifGraphRunHandler;

public class SarifTaintGraphRunHandler extends SarifGraphRunHandler {

	private TaintService service;

	@Override
	protected void populateVertex(Node n, AttributedVertex vertex) {
		if (service == null) {
			PluginTool tool = controller.getPlugin().getTool();
			service = tool.getService(TaintService.class);
		}
		Address addr = controller.locationToAddress(run, n.getLocation());
		vertex.setName(addr.toString());
		String text = n.getLabel().getText();
		PropertyBag properties = n.getProperties();
		if (properties != null) {
			Map<String, Object> additional = properties.getAdditionalProperties();
			if (additional != null) {
				for (Entry<String, Object> entry : additional.entrySet()) {
					vertex.setAttribute(entry.getKey(), entry.getValue().toString());
				}
			}
		}
		vertex.setAttribute("Label", text);
		vertex.setAttribute("Address", addr.toString(true));
		LogicalLocation ll = SarifUtils.getLogicalLocation(run, n.getLocation());
		if (ll != null) {
			String name = ll.getName();
			String fqname = ll.getFullyQualifiedName();
			String displayName = SarifUtils.extractDisplayName(ll);
			vertex.setAttribute("originalName", name);
			vertex.setAttribute("name", displayName);
			if (name != null) {
				vertex.setName(displayName);
			}
			addr = SarifUtils.getLocAddress(controller.getProgram(), fqname);
			if (addr != null) {
				vertex.setAttribute("Address", addr.toString(true));
			}

			vertex.setAttribute("location", fqname);
			vertex.setAttribute("kind", ll.getKind());
			vertex.setAttribute("function", SarifUtils.extractFQNameFunction(fqname));
			Address faddr = SarifUtils.extractFunctionEntryAddr(controller.getProgram(), fqname);
			if (faddr != null && faddr.getOffset() >= 0) {
				vertex.setAttribute("func_addr", faddr.toString(true));
			}
		}
	}

}
