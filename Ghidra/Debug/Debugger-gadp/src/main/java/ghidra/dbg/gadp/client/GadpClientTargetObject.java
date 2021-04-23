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

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;

import ghidra.dbg.agent.SpiTargetObject;
import ghidra.dbg.gadp.client.annot.GadpEventHandler;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.util.Msg;

public interface GadpClientTargetObject extends SpiTargetObject {
	Lookup LOOKUP = MethodHandles.lookup();

	@Override
	GadpClient getModel();

	@Override
	DelegateGadpClientTargetObject getDelegate();

	@GadpEventHandler(Gadp.EventNotification.EvtCase.MODEL_OBJECT_EVENT)
	default void handleModelObjectEvent(Gadp.EventNotification notification) {
		Gadp.ModelObjectEvent evt = notification.getModelObjectEvent();
		getDelegate().updateWithDeltas(evt.getElementDelta(), evt.getAttributeDelta());
	}

	@GadpEventHandler(Gadp.EventNotification.EvtCase.OBJECT_INVALIDATE_EVENT)
	default void handleObjectInvalidateEvent(Gadp.EventNotification notification) {
		Gadp.ObjectInvalidateEvent evt = notification.getObjectInvalidateEvent();
		getDelegate().invalidateSubtree(this, evt.getReason());
	}

	@GadpEventHandler(Gadp.EventNotification.EvtCase.CACHE_INVALIDATE_EVENT)
	default void handleCacheInvalidateEvent(Gadp.EventNotification notification) {
		getDelegate().doClearCaches();
	}

	@GadpEventHandler(Gadp.EventNotification.EvtCase.CONSOLE_OUTPUT_EVENT)
	default void handleConsoleOutputEvent(Gadp.EventNotification notification) {
		Gadp.ConsoleOutputEvent evt = notification.getConsoleOutputEvent();
		int channelIndex = evt.getChannel();
		Channel[] allChannels = Channel.values();
		if (0 <= channelIndex && channelIndex < allChannels.length) {
			getDelegate().getListeners().fire.consoleOutput(this, allChannels[channelIndex],
				evt.getData().toByteArray());
		}
		else {
			Msg.error(this, "Received output for unknown channel " + channelIndex + ": " +
				evt.getData().toString());
		}
	}
}
