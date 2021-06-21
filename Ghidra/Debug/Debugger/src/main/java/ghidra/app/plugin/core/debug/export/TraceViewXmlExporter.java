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
package ghidra.app.plugin.core.debug.export;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.util.*;
import ghidra.app.util.exporter.XmlExporter;
import ghidra.framework.model.DomainObject;
import ghidra.trace.model.Trace;

// TODO: perhaps getApplicableExporters should use domainObject's class, not file's object class.
// TODO: Where un-supported, be less abrasive, e.g., present empty managers.
public class TraceViewXmlExporter extends XmlExporter {
	private final Map<String, Object> hideOpts = Map.of(
		"Properties", false,
		"Relocation Table", false,
		"External Libraries", false);

	@Override
	public boolean canExportDomainObject(Class<? extends DomainObject> domainObjectClass) {
		return Trace.class.isAssignableFrom(domainObjectClass);
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		List<Option> options = super.getOptions(domainObjectService);
		return options.stream()
				.filter(o -> !hideOpts.keySet().contains(o.getName()))
				.collect(Collectors.toList());
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {
		List<Option> opts = new ArrayList<>(options);
		options.stream().filter(o -> !hideOpts.keySet().contains(o.getName())).forEach(opts::add);
		for (Map.Entry<String, Object> ent : hideOpts.entrySet()) {
			opts.add(new Option(ent.getKey(), ent.getValue()));
		}
		super.setOptions(opts);
	}
}
