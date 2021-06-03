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
package ghidra.framework.project.tool;

import java.util.*;

import org.jdom.Element;

import ghidra.framework.model.ToolConnection;
import ghidra.framework.model.ToolListener;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.datastruct.StringIntHashtable;
import ghidra.util.exception.NoValueException;

/**
 * Implementation for representing connections between two tools.
 * Acts as the middle man for the connection in order to filter the
 * events.
 */
class ToolConnectionImpl implements ToolConnection, ToolListener {

	private PluginTool producerTool;
	private PluginTool consumerTool;
	private StringIntHashtable connectHt; // maps event -> int value 1 if
	// tools are connected, int value 0 if tools are not connected

	private final static int CONNECTED = 1;
	private final static int DISCONNECTED = 0;

	private boolean listenerAdded; // set to true the first time a
	// connection is made for any event
	private boolean changed; // flag for whether the connection was changed

	/**
	 * Constructor
	 */
	ToolConnectionImpl(PluginTool producerTool, PluginTool consumerTool) {
		this.producerTool = producerTool;
		this.consumerTool = consumerTool;

		connectHt = new StringIntHashtable();
		updateEventList();
	}

	/**
	 * Default constructor used when there is a problem restoring state
	 * on the workspace; want the restore() method to still work.
	 */
	ToolConnectionImpl() {
	}

	/*
	 * @see ghidra.framework.model.ToolConnection#connect(java.lang.String)
	 */
	@Override
	public void connect(String eventName) {
		validateEventName(eventName);
		connectHt.put(eventName, CONNECTED);
		if (!listenerAdded) {
			producerTool.addToolListener(this);
			listenerAdded = true;
		}
		changed = true;
	}

	/*
	 * @see ghidra.framework.model.ToolConnection#isConnected(java.lang.String)
	 */
	@Override
	public boolean isConnected(String eventName) {
		if (!connectHt.contains(eventName)) {
			return false;
		}
		try {
			int value = connectHt.get(eventName);
			return (value == CONNECTED);

		}
		catch (NoValueException e) {
			return false;
		}

	}

	/*
	 * @see ghidra.framework.model.ToolConnection#getEvents()
	 */
	@Override
	public String[] getEvents() {
		String[] keys = connectHt.getKeys();
		Arrays.sort(keys);

		return keys;
	}

	/*
	 * @see ghidra.framework.model.ToolConnection#disconnect(java.lang.String)
	 */
	@Override
	public void disconnect(String eventName) {
		validateEventName(eventName);
		connectHt.put(eventName, DISCONNECTED);
		checkConnections();
		changed = true;
	}

	/*
	 * @see ghidra.framework.model.ToolConnection#getProducer()
	 */
	@Override
	public PluginTool getProducer() {
		return producerTool;
	}

	/*
	 * @see ghidra.framework.model.ToolConnection#getConsumer()
	 */
	@Override
	public PluginTool getConsumer() {
		return consumerTool;
	}

	/*
	 * @see ghidra.framework.model.ToolListener#processToolEvent(ghidra.framework.model.ToolEvent)
	 */
	@Override
	public void processToolEvent(PluginEvent toolEvent) {

		if (isConnected(toolEvent.getToolEventName())) {
			consumerTool.processToolEvent(toolEvent);
		}
	}

	/**
	 * Saves the Tool Connection into an XML element.
	 */
	public Element saveToXml() {
		Element root = new Element("CONNECTION");
		root.setAttribute("PRODUCER", producerTool.getName());
		root.setAttribute("CONSUMER", consumerTool.getName());
		root.setAttribute("LISTENER_ADDED", "" + listenerAdded);
		String[] keys = connectHt.getKeys();
		for (String key : keys) {
			Element elem = new Element("EVENT");
			elem.setAttribute("NAME", key);
			int val = DISCONNECTED;
			try {
				val = connectHt.get(key);
			}
			catch (NoValueException nve) {
			}
			elem.setAttribute("CONNECTED", (val == CONNECTED ? "true" : "false"));
			root.addContent(elem);
		}
		changed = false;
		return root;
	}

	/**
	 * restores the ToolConnection from an XML element
	 * 
	 * @param root XML element to restore ToolConnection from.
	 */
	public void restoreFromXml(Element root) {
		listenerAdded = false;

		Iterator<?> iter = root.getChildren("EVENT").iterator();
		while (iter.hasNext()) {
			Element elem = (Element) iter.next();
			String name = elem.getAttributeValue("NAME");
			String state = elem.getAttributeValue("CONNECTED");
			boolean connected = (state != null && state.equalsIgnoreCase("true"));
			connectHt.put(name, (connected ? CONNECTED : DISCONNECTED));
			if (connected && !listenerAdded) {
				producerTool.addToolListener(this);
				listenerAdded = true;
			}
		}
	}

	/**
	 * Returns a hash code value for the object. This method is
	 * supported for the benefit of hashtables such as those provided by
	 * <code>java.util.Hashtable</code>.
	 */
	@Override
	public int hashCode() {
		return producerTool.getName().hashCode() +
			consumerTool.getName().hashCode();
	}

	/**
	 * Indicates whether some other object is "equal to" this one.
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		ToolConnectionImpl tc = (ToolConnectionImpl) obj;

		return producerTool.getName().equals(tc.producerTool.getName()) &&
			consumerTool.getName().equals(tc.consumerTool.getName());
	}

	/**
	 * Returns a string representation of the object. In general, the
	 * <code>toString</code> method returns a string that
	 * "textually represents" this object. The result should
	 * be a concise but informative representation that is easy for a
	 * person to read.
	 */
	@Override
	public String toString() {
		return "Producer=" + producerTool.getName() +
			", Consumer=" + consumerTool.getName();
	}

	////////////////////////////////////////////////////////////////
	// ** package methods
	///////////////////////////////////////////////////////////////
	/**
	 * Return true if the connection changed.
	 */
	boolean hasChanged() {
		return changed;
	}

	/**
	 * Update the events that are consumed and produced, as the tool
	 * may have added or removed plugins.
	 */
	void updateEventList() {

		String[] producerEvents = producerTool.getToolEventNames();
		String[] consumedEvents = consumerTool.getConsumedToolEventNames();
		List<String> pList = Arrays.asList(producerEvents);
		List<String> cList = Arrays.asList(consumedEvents);
		ArrayList<String> producerList = new ArrayList<>(pList);
		ArrayList<String> consumerList = new ArrayList<>(cList);

		// get the intersection of the lists
		producerList.retainAll(consumerList);
		consumerList.retainAll(producerList);

		for (int i = 0; i < producerList.size(); i++) {
			String event = producerList.get(i);
			if (!connectHt.contains(event)) {
				connectHt.put(event, DISCONNECTED);
			}
		}
		String[] keys = connectHt.getKeys();
		for (String key : keys) {
			if (!producerList.contains(key)) {
				connectHt.remove(key);
			}
		}
	}

	////////////////////////////////////////////////////////////////
	// ** private methods
	////////////////////////////////////////////////////////////////

	/**
	 *  Verify that the given event name is produced by the
	 * producer tool and is consumed by the consumer tool.
	 * 
	 * @throws IllegalArgumentException if the event is not in the
	 * list of events for this producer/consumer pair.
	 */
	private void validateEventName(String eventName) {
		if (!connectHt.contains(eventName)) {
			throw new IllegalArgumentException("Event name " + eventName +
				" is not valid for producer " +
				producerTool.getName() + ", consumer " +
				consumerTool.getName());
		}
	}

	/**
	 * Check the connections; if there are none, then remove the
	 * consumer tool as a listener on the producer tool; called
	 * when a disconnect is made.
	 */
	private void checkConnections() {

		String[] eventNames = connectHt.getKeys();
		boolean connectionFound = false;
		for (String eventName : eventNames) {
			try {
				int value = connectHt.get(eventName);
				if (value == CONNECTED) {
					connectionFound = true;
					break;
				}
			}
			catch (NoValueException e) {
				Msg.showError(this, null, "Error", "Event name not in table: " + e.getMessage());
			}
		}
		if (!connectionFound) {
			producerTool.removeToolListener(this);
			listenerAdded = false;
		}
	}
}
