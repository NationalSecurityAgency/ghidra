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

import java.util.Collection;
import java.util.List;

import ghidra.dbg.gadp.client.annot.GadpAttributeChangeCallback;
import ghidra.dbg.gadp.client.annot.GadpEventHandler;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetConsole.TargetConsoleListener;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.ValueUtils;
import ghidra.util.Msg;

public interface GadpClientTargetObject extends TargetObject {
	@Override
	GadpClient getModel();

	@Override
	List<String> getProtocolID();

	@Override
	String getTypeHint();

	@Override
	Collection<String> getInterfaceNames();

	@Override
	Collection<Class<? extends TargetObject>> getInterfaces();

	DelegateGadpClientTargetObject getDelegate();

	@GadpEventHandler(Gadp.EventNotification.EvtCase.MODEL_OBJECT_EVENT)
	default void handleModelObjectEvent(Gadp.EventNotification notification) {
		Gadp.ModelObjectEvent evt = notification.getModelObjectEvent();
		getDelegate().updateWithDelta(evt.getDelta());
	}

	@GadpEventHandler(Gadp.EventNotification.EvtCase.OBJECT_INVALIDATE_EVENT)
	default void handleObjectInvalidateEvent(Gadp.EventNotification notification) {
		Gadp.ObjectInvalidateEvent evt = notification.getObjectInvalidateEvent();
		getDelegate().doInvalidateSubtree(evt.getReason());
	}

	@GadpEventHandler(Gadp.EventNotification.EvtCase.CACHE_INVALIDATE_EVENT)
	default void handleCacheInvalidateEvent(Gadp.EventNotification notification) {
		getDelegate().doClearCaches();
	}

	default String displayFromObj(Object obj) {
		return ValueUtils.expectType(obj, String.class, this, DISPLAY_ATTRIBUTE_NAME, getName());
	}

	@GadpAttributeChangeCallback(DISPLAY_ATTRIBUTE_NAME)
	default void handleDisplayChanged(Object display) {
		getDelegate().listeners.fire.displayChanged(this, displayFromObj(display));
	}

	// TODO: It's odd to put this here.... I think it indicates a problem in the API
	@GadpEventHandler(Gadp.EventNotification.EvtCase.CONSOLE_OUTPUT_EVENT)
	default void handleConsoleOutputEvent(Gadp.EventNotification notification) {
		Gadp.ConsoleOutputEvent evt = notification.getConsoleOutputEvent();
		int channelIndex = evt.getChannel();
		Channel[] allChannels = Channel.values();
		if (0 <= channelIndex && channelIndex < allChannels.length) {
			getDelegate().listeners.fire(TargetConsoleListener.class)
					.consoleOutput(this, allChannels[channelIndex], evt.getData().toByteArray());
		}
		else {
			Msg.error(this, "Received output for unknown channel " + channelIndex + ": " +
				evt.getData().toString());
		}
	}
}
