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
package ghidra.trace.model.modules;

import java.util.Collection;

import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.module.TraceObjectSection;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * A binary module loaded by the target and/or debugger
 * 
 * <p>
 * If the debugger cares to parse the modules for section information, those sections should be
 * presented as successors to the module.
 */
@TraceObjectInfo(
	schemaName = "Module",
	shortName = "module",
	attributes = {
		TraceObjectModule.KEY_RANGE,
		TraceObjectModule.KEY_MODULE_NAME,
	},
	fixedKeys = {
		TraceObjectModule.KEY_DISPLAY,
		TraceObjectModule.KEY_RANGE,
	})
public interface TraceObjectModule extends TraceModule, TraceObjectInterface {
	String KEY_RANGE = "_range";
	String KEY_MODULE_NAME = "_module_name";

	void setName(Lifespan lifespan, String name);

	void setRange(Lifespan lifespan, AddressRange range);

	@Override
	Collection<? extends TraceObjectSection> getSections();

	@Override
	TraceObjectSection getSectionByName(String sectionName);
}
