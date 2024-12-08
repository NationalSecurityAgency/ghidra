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
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetThread;
import ghidra.debug.flatapi.FlatDebuggerRecorderAPI;;

public class MonitorModelEventsScript extends GhidraScript implements FlatDebuggerRecorderAPI {
	static DebuggerModelListener listener = new DebuggerModelListener() {
		@Override
		public void attributesChanged(TargetObject object, Collection<String> removed,
				Map<String, ?> added) {
			System.err.println("attributesChanged(%s, removed=%s, added=%s)"
					.formatted(object.getJoinedPath("."), removed, added));
		}

		@Override
		public void elementsChanged(TargetObject object, Collection<String> removed,
				Map<String, ? extends TargetObject> added) {
			System.err.println("elementsChanged(%s, removed=%s, added=%s)"
					.formatted(object.getJoinedPath("."), removed, added));
		}

		@Override
		public void event(TargetObject object, TargetThread eventThread, TargetEventType type,
				String description, List<Object> parameters) {
			System.err.println(
				"event(%s, thread=%s, type=%s, desc=%s)".formatted(object.getJoinedPath("."),
					eventThread == null ? "<null>" : eventThread.getJoinedPath("."), type,
					description));
		}

		@Override
		public void invalidateCacheRequested(TargetObject object) {
			System.err.println("invalidateCache(%s)".formatted(object.getJoinedPath(".")));
		}
	};

	@Override
	protected void run() throws Exception {
		getModelService().getCurrentModel().addModelListener(listener);
	}
}
