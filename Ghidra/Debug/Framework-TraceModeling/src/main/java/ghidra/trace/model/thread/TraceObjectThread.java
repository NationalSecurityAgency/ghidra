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
package ghidra.trace.model.thread;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetThread;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObjectInterface;
import ghidra.trace.model.target.annot.TraceObjectInfo;

@TraceObjectInfo(
	targetIf = TargetThread.class,
	shortName = "thread",
	fixedKeys = {
		TargetObject.DISPLAY_ATTRIBUTE_NAME,
		TraceObjectThread.KEY_COMMENT
	})
public interface TraceObjectThread extends TraceThread, TraceObjectInterface {
	String KEY_COMMENT = "_comment";

	void setName(Lifespan lifespan, String name);
}
