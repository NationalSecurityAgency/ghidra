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
package ghidra.framework.plugintool.mgr;

import java.util.*;

import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.collections4.map.LazyMap;

import ghidra.framework.model.ToolListener;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginEventListener;
import ghidra.util.Msg;
import ghidra.util.Swing;

/**
 * Helper class to manage the events that plugins consume and produce. This class keeps track of the
 * last events that went out so that when a plugin is added, it receives those events.
 */
public class EventManager {
	private List<ToolListener> toolListeners = new ArrayList<>();
	private Map<Class<? extends PluginEvent>, Set<PluginEventListener>> listenersByEventType =
		LazyMap.lazyMap(new HashMap<>(), clazz -> new HashSet<>());
	private Map<String, Counter> producerMap =
		LazyMap.lazyMap(new HashMap<>(), name -> new Counter());
	private Map<String, Counter> consumerMap =
		LazyMap.lazyMap(new HashMap<>(), name -> new Counter());
	private LinkedHashMap<Class<? extends PluginEvent>, PluginEvent> lastEventsByType =
		new LinkedHashMap<>();
	private LinkedList<PluginEvent> eventQ = new LinkedList<>();
	private Set<PluginEventListener> allEventListeners = new HashSet<>();

	private PluginTool tool;
	private PluginEvent currentEvent;
	private final Runnable sendEventsRunnable = () -> sendEvents();
	private volatile boolean sendingToolEvent;

	/**
	 * Construct a new EventManager.
	 * 
	 * @param tool plugin tool associated with this EventManager
	 */
	public EventManager(PluginTool tool) {
		this.tool = tool;
	}

	/**
	 * Add a plugin event listener that will be notified when an event of the given event class is
	 * generated.
	 * 
	 * @param eventClass class of the event of interest
	 * @param listener listener to notify
	 */
	public void addEventListener(Class<? extends PluginEvent> eventClass,
			PluginEventListener listener) {
		Set<PluginEventListener> set = listenersByEventType.get(eventClass);
		if (set.isEmpty()) {
			String name = PluginEvent.lookupToolEventName(eventClass);
			if (name != null) {
				consumerMap.get(name).count++;
			}
		}
		set.add(listener);
	}

	public void addAllEventListener(PluginEventListener listener) {
		allEventListeners.add(listener);
	}

	public void removeAllEventListener(PluginEventListener listener) {
		allEventListeners.remove(listener);
	}

	/**
	 * Remove the plugin event listener from the list of listeners notified when an event of the
	 * given event class is generated.
	 * 
	 * @param eventClass class of the event of interest
	 * @param listener listener to remove
	 */
	public void removeEventListener(Class<? extends PluginEvent> eventClass,
			PluginEventListener listener) {
		Set<PluginEventListener> set = listenersByEventType.get(eventClass);
		set.remove(listener);
		if (set.isEmpty()) {
			eventConsumerRemoved(eventClass);
		}
	}

	private void eventConsumerRemoved(Class<? extends PluginEvent> eventClass) {
		String name = PluginEvent.lookupToolEventName(eventClass);
		if (name == null) {
			return;
		}

		Counter counter = consumerMap.get(name);
		if (--counter.count == 0) {
			consumerMap.remove(name);
		}
	}

	/**
	 * Add the given tool listener to be notified notified when tool events are generated
	 * 
	 * @param listener listener to add
	 */
	public void addToolListener(ToolListener listener) {
		toolListeners.add(listener);
	}

	/**
	 * Remove the given tool listener from the list of tool listeners
	 * 
	 * @param listener listener to remove
	 */
	public void removeToolListener(ToolListener listener) {
		toolListeners.remove(listener);
	}

	/**
	 * Return whether there are any registered tool listeners for the tool associated with class
	 * 
	 * @return true if there are any listeners
	 */
	public boolean hasToolListeners() {
		return !toolListeners.isEmpty();
	}

	/**
	 * Add the class for the PluginEvent that a plugin will produce
	 * 
	 * @param eventClass class for the PluginEvent
	 */
	public void addEventProducer(Class<? extends PluginEvent> eventClass) {
		String name = PluginEvent.lookupToolEventName(eventClass);
		if (name != null) {
			Counter counter = producerMap.get(name);
			counter.count++;
		}
	}

	/**
	 * Remove the class of a PluginEvent that a plugin produces.
	 * 
	 * @param eventClass class for the PluginEvent
	 */
	public void removeEventProducer(Class<? extends PluginEvent> eventClass) {
		String name = PluginEvent.lookupToolEventName(eventClass);
		if (name == null) {
			return;
		}

		Counter counter = producerMap.get(name);
		if (--counter.count == 0) {
			producerMap.remove(name);
		}
	}

	/**
	 * Get the names of all events produced by plugins in the tool.
	 * 
	 * @return array of PluginEvent names
	 */
	public String[] getEventsProduced() {
		return producerMap.keySet().toArray(new String[producerMap.size()]);
	}

	/**
	 * Get the names of all events consumed by plugins in the tool.
	 * 
	 * @return array of PluginEvent names
	 */
	public String[] getEventsConsumed() {
		return consumerMap.keySet().toArray(new String[consumerMap.size()]);
	}

	/**
	 * Notify all plugin listeners that are registered to consume the given event. Events are fired
	 * in the SwingThread.
	 * 
	 * @param event event to fire
	 */
	public void fireEvent(PluginEvent event) {

		synchronized (eventQ) {
			if (currentEvent != null) {
				if (validateEventChain(currentEvent, event)) {

					// note: it is a bit odd that we assume any event passed to this method is 
					//       triggered by that event.  This may not be the case if we are on a 
					//       background thread.
					event.setTriggerEvent(currentEvent);
					eventQ.add(event);
				}

				return; // allow the current event processing to finish
			}
		}

		// no event processing running right now; start it
		eventQ.add(event);
		Swing.runNow(sendEventsRunnable);
	}

	private boolean validateEventChain(PluginEvent startEvent, PluginEvent newEvent) {
		while (startEvent != null) {
			if (startEvent.getClass().isAssignableFrom(newEvent.getClass()) &&
				startEvent.getEventName().equals(newEvent.getEventName())) {
				return false;
			}
			startEvent = startEvent.getTriggerEvent();
		}
		return true;
	}

	/**
	 * Convert the given tool event to a plugin event; notify the appropriate plugin listeners. This
	 * method allows one tool's event manager to send events to another connected tool.
	 * 
	 * @param event tool event
	 */
	public void processToolEvent(PluginEvent event) {
		// only process the event if we are the receiving tool
		if (!sendingToolEvent) {
			fireEvent(event);
		}
	}

	/**
	 * Clear the list of last plugin events fired
	 */
	public void clearLastEvents() {
		lastEventsByType.clear();
	}

	/**
	 * Clear last plugin events fired, current event, listeners, etc.
	 */
	public void clear() {
		allEventListeners.clear();
		toolListeners.clear();
		currentEvent = null;
		lastEventsByType.clear();
		listenersByEventType.clear();
		eventQ.clear();
	}

	/**
	 * Return an array of the last plugin events fired. EventManager maps the event class to the
	 * last event fired.
	 * 
	 * @return array of plugin events
	 */
	public PluginEvent[] getLastEvents() {
		return lastEventsByType.values().toArray(new PluginEvent[lastEventsByType.size()]);
	}

	private void sendEvents() {

		Swing.assertSwingThread("Events must be sent on the Swing thread");

		synchronized (eventQ) {
			currentEvent = eventQ.poll();
		}

		while (currentEvent != null) {
			Class<? extends PluginEvent> eventClass = currentEvent.getClass();
			lastEventsByType.put(eventClass, currentEvent);

			for (PluginEventListener listener : getListeners(eventClass)) {
				try {
					listener.eventSent(currentEvent);
				}
				catch (Throwable t) {
					Msg.showError(this, tool.getToolFrame(), "Plugin Event Error",
						"Error in plugin event listener", t);
				}
			}

			sendToolEvent(currentEvent);

			synchronized (eventQ) {
				currentEvent = eventQ.poll();
			}
		}
		tool.contextChanged(null);
	}

	private Iterable<PluginEventListener> getListeners(Class<? extends PluginEvent> eventClass) {
		Set<PluginEventListener> specificListeners = listenersByEventType.get(eventClass);
		return IterableUtils.chainedIterable(specificListeners, allEventListeners);
	}

	// note: this is expected to be on the Swing thread, called from sendEvent()
	private void sendToolEvent(PluginEvent event) {
		if (toolListeners.isEmpty()) {
			return;
		}

		if (!event.isToolEvent()) {
			return;
		}

		sendingToolEvent = true;
		try {
			event.setSourceName(PluginEvent.EXTERNAL_SOURCE_NAME);
			event.setTriggerEvent(null);
			for (int i = 0; i < toolListeners.size(); i++) {
				ToolListener tl = toolListeners.get(i);

				try {
					tl.processToolEvent(event);
				}
				catch (Throwable t) {
					Msg.showError(this, tool.getToolFrame(), "Plugin Event Error",
						"Error sending event to connected tool", t);
				}
			}
		}
		finally {
			sendingToolEvent = false;
		}
	}

	/**
	 * Remove the event listener by className; the plugin registered for events, but the
	 * construction failed.
	 * 
	 * @param className class name of the plugin (event listener)
	 */
	public void removeEventListener(String className) {

		List<Class<? extends PluginEvent>> unusedList = new ArrayList<>();

		Iterator<Class<? extends PluginEvent>> iter = listenersByEventType.keySet().iterator();
		while (iter.hasNext()) {
			Class<? extends PluginEvent> eventClass = iter.next();
			Set<PluginEventListener> set = listenersByEventType.get(eventClass);
			Iterator<PluginEventListener> it = set.iterator();
			while (it.hasNext()) {
				PluginEventListener listener = it.next();
				if (listener.getClass().getName().equals(className)) {
					it.remove();
					if (set.isEmpty()) {
						unusedList.add(eventClass);
					}
					break;
				}
			}
		}

		for (int i = 0; i < unusedList.size(); i++) {
			Class<? extends PluginEvent> eventClass = unusedList.get(i);
			eventConsumerRemoved(eventClass);
		}
	}

}

class Counter {
	int count = 0;
}
