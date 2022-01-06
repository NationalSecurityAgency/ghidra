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

import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetObject;
import ghidra.trace.database.module.TraceObjectSection;
import ghidra.trace.model.target.TraceObjectInterface;
import ghidra.trace.model.target.annot.TraceObjectInfo;

@TraceObjectInfo(
	targetIf = TargetModule.class,
	shortName = "module",
	fixedKeys = {
		TargetObject.DISPLAY_ATTRIBUTE_NAME,
		TargetModule.RANGE_ATTRIBUTE_NAME
	})
public interface TraceObjectModule extends TraceModule, TraceObjectInterface {
	@Override
	Collection<? extends TraceObjectSection> getSections();

	@Override
	TraceObjectSection getSectionByName(String sectionName);
}
