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
package ghidra.trace.database.module;

import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * An allocated section of a binary module
 * 
 * <p>
 * Note that the model should only present those sections which are allocated in memory. Otherwise
 * strange things may happen, such as zero-length ranges (which AddressRange hates), or overlapping
 * ranges (which Trace hates).
 * 
 * <p>
 * TODO: Present all sections, but include isAllocated?
 */
@TraceObjectInfo(
	schemaName = "Section",
	shortName = "section",
	attributes = {
		TraceObjectSection.KEY_MODULE,
		TraceObjectSection.KEY_RANGE,
	},
	fixedKeys = {
		TraceObjectInterface.KEY_DISPLAY,
		TraceObjectSection.KEY_RANGE
	})
public interface TraceObjectSection extends TraceSection, TraceObjectInterface {
	String KEY_MODULE = "_module";
	String KEY_RANGE = "_range";

	void setName(Lifespan lifespan, String name);

	void setRange(Lifespan lifespan, AddressRange range);
}
