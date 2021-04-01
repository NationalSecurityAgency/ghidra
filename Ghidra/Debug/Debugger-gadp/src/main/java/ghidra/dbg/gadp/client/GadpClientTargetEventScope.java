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
package ghidra.dbg.gadp.client;

import java.util.List;

import ghidra.dbg.gadp.client.annot.GadpEventHandler;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.target.TargetEventScope;
import ghidra.dbg.target.TargetThread;

public interface GadpClientTargetEventScope extends GadpClientTargetObject, TargetEventScope {
	@GadpEventHandler(Gadp.EventNotification.EvtCase.TARGET_EVENT)
	default void handleDebuggerEvent(Gadp.EventNotification notification) {
		Gadp.TargetEvent evt = notification.getTargetEvent();
		Gadp.Path threadPath = evt.getEventThread();
		TargetThread thread = threadPath == null || threadPath.getECount() == 0 ? null
				: getModel().getProxy(threadPath.getEList(), true).as(TargetThread.class);
		TargetEventType type = GadpValueUtils.getTargetEventType(evt.getType());
		String description = evt.getDescription();
		List<Object> parameters =
			GadpValueUtils.getValues(getModel(), evt.getParametersList());
		getDelegate().getListeners().fire.event(this, thread, type, description, parameters);
	}
}
