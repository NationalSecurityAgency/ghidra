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

import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.SwingUtilities;

import ghidra.framework.model.ToolListener;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginEventListener;
import ghidra.util.Msg;

/**
 * Helper class to manage the events that plugins consume and produce.
 * This class keeps track of the last events that went out so that when
 * a plugin is added, it receives those events. 
 *
 */
public class EventManager {
	private ArrayList<ToolListener> toolListeners = new ArrayList<>();
	private HashMap<Class<? extends PluginEvent>, Set<PluginEventListener>> pluginListenerMap =
		new HashMap<>();
	private HashMap<String, Counter> producerMap = new HashMap<>();
	private HashMap<String, Counter> consumerMap = new HashMap<>();
	private LinkedHashMap<Class<? extends PluginEvent>, PluginEvent> lastEvents =
		new LinkedHashMap<>();
	private LinkedList<PluginEvent> eventQ = new LinkedList<>();
	private Set<PluginEventListener> allEventListeners = new HashSet<>();

	private PluginEvent currentEvent;
	private Runnable sendEventsRunnable;
	private PluginTool tool;
	private boolean sendingToolEvent;

	/**
	 * Construct a new EventManager.
	 * @param tool plugin tool associated with this EventManager
	 */
	public EventManager(PluginTool tool) {
		this.tool = tool;

		sendEventsRunnable = () -> sendEvents();
	}

	/**
	 * Add a plugin event listener that will be notified when an event of
	 * the given event class is generated.
	 * @param eventClass class of the event of interest
	 * @param listener listener to notify
	 */
	public void addEventListener(Class<? extends PluginEvent> eventClass,
			PluginEventListener listener) {
		Set<PluginEventListener> set = pluginListenerMap.get(eventClass);
		if (set == null) {
			set = new HashSet<>();
			pluginListenerMap.put(eventClass, set);
			String name = PluginEvent.lookupToolEventName(eventClass);
			if (name != null) {
				Counter counter = consumerMap.get(name);
				if (counter == null) {
					counter = new Counter();
					consumerMap.put(name, counter);
				}
				counter.count++;
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
	 * Remove the plugin event listener from the list of listeners notified
	 * when an event of the given event class is generated.
	 * @param eventClass class of the event of interest
	 * @param listener listener to remove
	 */
	public void removeEventListener(Class<? extends PluginEvent> eventClass,
			PluginEventListener listener) {
		Set<PluginEventListener> set = pluginListenerMap.get(eventClass);
		if (set != null) {
			set.remove(listener);
			if (set.size() == 0) {
				pluginListenerMap.remove(eventClass);
				String name = PluginEvent.lookupToolEventName(eventClass);
				if (name != null) {
					Counter counter = consumerMap.get(name);
					if (counter != null && --counter.count == 0) {
						consumerMap.remove(name);
					}
				}
			}
		}
	}

	/**
	 * Add the given tool listener to a list of tool listeners notified
	 * when tool events are generated.
	 * @param listener listener to add
	 */
	public void addToolListener(ToolListener listener) {
		toolListeners.add(listener);
	}

	/**
	 * Remove the given tool listener from the list of tool listeners.
	 * @param listener listener to remove
	 */
	public void removeToolListener(ToolListener listener) {
		toolListeners.remove(listener);
	}

	/**
	 * Return whether there are any registered tool listeners for the
	 * tool associated with this EventManager.
	 */
	public boolean hasToolListeners() {
		return !toolListeners.isEmpty();
	}

	/**
	 * Add the class for the PluginEvent that a plugin will produce.   
	 * @param eventClass class for the PluginEvent
	 */
	public void addEventProducer(Class<? extends PluginEvent> eventClass) {
		String name = PluginEvent.lookupToolEventName(eventClass);
		if (name != null) {
			Counter counter = producerMap.get(name);
			if (counter == null) {
				counter = new Counter();
				producerMap.put(name, counter);
			}
			counter.count++;
		}
	}

	/**
	 * Remove the class of a PluginEvent that a plugin produces.
	 * @param eventClass class for the PluginEvent
	 */
	public void removeEventProducer(Class<? extends PluginEvent> eventClass) {
		String name = PluginEvent.lookupToolEventName(eventClass);
		if (name != null) {
			Counter counter = producerMap.get(name);
			if (counter != null && --counter.count == 0) {
				producerMap.remove(name);
			}
		}
	}

	/**
	 * Get the names of all events produced by plugins in the tool.
	 * @return array of PluginEvent names
	 */
	public String[] getEventsProduced() {
		return producerMap.keySet().toArray(new String[producerMap.size()]);
	}

	/**
	 * Get the names of all events consumed by plugins in the tool.
	 * @return array of PluginEvent names
	 */
	public String[] getEventsConsumed() {
		return consumerMap.keySet().toArray(new String[consumerMap.size()]);
	}

	/**
	 * Notify all plugin listeners that are registered to consume the given
	 * event. Events are fired in the SwingThread. 
	 * @param event event to fire
	 */
	public void fireEvent(PluginEvent event) {

		synchronized (eventQ) {
			if (currentEvent != null) {
				if (validateEventChain(event)) {
					event.setTriggerEvent(currentEvent);
					eventQ.add(event);
				}
				return;
			}
			currentEvent = event;
		}

		if (SwingUtilities.isEventDispatchThread()) {
			sendEvents();
		}
		else {
			try {
				SwingUtilities.invokeAndWait(sendEventsRunnable);
			}
			catch (InterruptedException e) {
			}
			catch (InvocationTargetException e) {
			}
		}
	}

	/**
	 * Convert the given tool event to a plugin event, and notify the
	 * appropriate plugin event listeners.
	 * @param event tool event
	 */
	public void processToolEvent(PluginEvent event) {
		if (!sendingToolEvent) {
			fireEvent(event);
		}
	}

	/**
	 * Clear the list of last plugin events fired.
	 *
	 */
	public void clearLastEvents() {
		lastEvents.clear();
	}

	/**
	 * Return an array of the last plugin events fired. EventManager 
	 * maps the event class to the last event fired.
	 * @return array of plugin events
	 */
	public PluginEvent[] getLastEvents() {
		return lastEvents.values().toArray(new PluginEvent[lastEvents.size()]);
	}

	/**
	 * Send all events on the queue
	 */
	private void sendEvents() {

		while (currentEvent != null) {
			Class<? extends PluginEvent> eventClass = currentEvent.getClass();
			lastEvents.remove(eventClass);
			lastEvents.put(eventClass, currentEvent);

			Set<PluginEventListener> set = pluginListenerMap.get(eventClass);
			if (set != null) {
				for (PluginEventListener listener : set) {
					try {
						listener.eventSent(currentEvent);
					}
					catch (Throwable t) {
						Msg.showError(this, tool.getToolFrame(), "Plugin Event Error",
							"Error in plugin event listener", t);
					}
				}
			}
			for (PluginEventListener pluginEventListener : allEventListeners) {
				pluginEventListener.eventSent(currentEvent);
			}
			sendToolEvent();
			synchronized (eventQ) {
				currentEvent = eventQ.isEmpty() ? null : (PluginEvent) eventQ.removeFirst();
			}
		}
		tool.contextChanged(null);
	}

	private void sendToolEvent() {
		if (!toolListeners.isEmpty() && currentEvent.isToolEvent()) {
			sendingToolEvent = true;
			try {
				currentEvent.setSourceName(PluginEvent.EXTERNAL_SOURCE_NAME);
				currentEvent.setTriggerEvent(null);
				for (int i = 0; i < toolListeners.size(); i++) {
					ToolListener tl = toolListeners.get(i);
					tl.processToolEvent(currentEvent);
				}
			}
			finally {
				sendingToolEvent = false;
			}
		}
	}

	private boolean validateEventChain(PluginEvent event) {
		PluginEvent tempEvent = currentEvent;
		while (tempEvent != null) {
			if (tempEvent.getClass().isAssignableFrom(event.getClass()) &&
				tempEvent.getEventName().equals(event.getEventName())) {
				return false;
			}
			tempEvent = tempEvent.getTriggerEvent();
		}
		return true;
	}

	/**
	 * Remove the event listener by className; the plugin registered for
	 * events, but the construction failed.
	 * @param className class name of the plugin (event listener)
	 */
	public void removeEventListener(String className) {
		ArrayList<Class<? extends PluginEvent>> unusedList =
			new ArrayList<>();

		Iterator<Class<? extends PluginEvent>> iter = pluginListenerMap.keySet().iterator();
		while (iter.hasNext()) {
			Class<? extends PluginEvent> eventClass = iter.next();
			Set<PluginEventListener> set = pluginListenerMap.get(eventClass);
			Iterator<PluginEventListener> iterator = set.iterator();
			for (; iterator.hasNext();) {
				PluginEventListener listener = iterator.next();
				if (listener.getClass().getName().equals(className)) {
					iterator.remove();
					if (set.size() == 0) {
						unusedList.add(eventClass);
					}
					break;
				}
			}
		}
		for (int i = 0; i < unusedList.size(); i++) {
			Class<? extends PluginEvent> eventClass = unusedList.get(i);
			pluginListenerMap.remove(eventClass);
			String name = PluginEvent.lookupToolEventName(eventClass);
			if (name != null) {
				Counter counter = consumerMap.get(name);
				if (counter != null && --counter.count == 0) {
					consumerMap.remove(name);
				}
			}
		}
	}

}

class Counter {
	int count = 0;
}
