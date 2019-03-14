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
package ghidra.app.plugin.debug;

import java.awt.Font;
import java.lang.reflect.Field;
import java.util.Date;

import docking.help.Help;
import docking.help.HelpService;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.datastruct.IntObjectHashtable;

/**
  * Debug Plugin to show domain object change events.
  */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.TESTING,
	shortDescription = "Displays domain object events",
	description = "This plugin provides a component to display domain object event " +
			"as they are generated. The maximum number of messages shown is " +
			DomainEventComponentProvider.LIMIT + ".  Useful for debugging.",
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class DomainEventDisplayPlugin extends Plugin implements DomainObjectListener {

	private Program currentProgram;
	private DomainEventComponentProvider provider;
	private IntObjectHashtable<String> eventHt;
	private String padString;

	/**
	  * Constructor
	  */
	public DomainEventDisplayPlugin(PluginTool tool) {

		super(tool);

		eventHt = new IntObjectHashtable<>();
		String dateStr = new Date() + ": ";
		padString = dateStr.replaceAll(".", " ");

		provider = new DomainEventComponentProvider(tool, getName());

		// Note: this plugin in the 'Developer' category and as such does not need help 
		HelpService helpService = Help.getHelpService();
		helpService.excludeFromHelp(provider);
	}

	/**
	 * Put event processing code here.
	 */
	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program newProg = ev.getActiveProgram();
			if (currentProgram != null) {
				currentProgram.removeListener(this);
			}
			if (newProg != null) {
				newProg.addListener(this);
			}
		}
	}

	/**
	 * Tells a plugin that it is no longer needed.  The plugin should remove
	 * itself from anything that it is registered to and release any resources.
	 */
	@Override
	public void dispose() {
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
	}

	/**
	 * This is the callback method for DomainObjectChangedEvents.
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (tool != null && provider.isVisible()) {
			update(ev);
		}
	}

	/**
	 * Get the font for the text area; font property will show up on the
	 * plugin property sheet.
	 */
	public Font getFont() {
		return provider.getFont();
	}

	/**
	 * Set the font for the text area; font property will show up on the
	 * plugin property sheet.
	
	 */
	public void setFont(Font font) {
		provider.setFont(font);
		tool.setConfigChanged(true);
	}

	/**
	 * Apply the updates that are in the change event.
	 */
	private void update(DomainObjectChangedEvent event) {
		for (int i = 0; i < event.numRecords(); i++) {
			String s = null;
			String start = null;
			String end = null;
			String oldValue = null;
			String newValue = null;
			String affectedObj = null;
			String dateStr = new Date() + ": ";
			int eventType = 0;

			DomainObjectChangeRecord docr = event.getChangeRecord(i);
			eventType = docr.getEventType();
			if (docr instanceof ProgramChangeRecord) {
				ProgramChangeRecord record = (ProgramChangeRecord) docr;

				try {
					start = "" + record.getStart();
					end = "" + record.getEnd();
					oldValue = "" + record.getOldValue();
					newValue = "" + record.getNewValue();
					affectedObj = "" + record.getObject();
				}
				catch (Exception e) {
					s = dateStr + getEventName(eventType) + " (" + eventType +
						") => *** Event data is not available ***\n";
				}
			}
			else if (docr instanceof CodeUnitPropertyChangeRecord) {
				CodeUnitPropertyChangeRecord record = (CodeUnitPropertyChangeRecord) docr;
				s = dateStr + getEventName(eventType) + " (" + eventType + ") ==> propertyName = " +
					record.getPropertyName() + ", code unit address = " + record.getAddress() +
					" old value = " + record.getOldValue() + ", new value = " +
					record.getNewValue() + "\n";
			}
			else {
				s = getEventName(eventType, DomainObject.class);
				if (s != null) {
					s = dateStr + "DomainObject Event (" + eventType + "): " + s + "\n";
				}
			}
			if (s == null) {
				s = dateStr + getEventName(eventType) + " (" + eventType + ") => start param = " +
					start + ", end param = " + end + "\n" + padString + "old value = " + oldValue +
					", new value = " + newValue + ", affected object = " + affectedObj +
					", (source=" + event.getSource() + ")\n";
			}
			provider.displayEvent(s);
		}
	}

	/**
	 * Use reflection to get the name of the given eventType.
	 */
	private String getEventName(int eventType) {

		String eventName = eventHt.get(eventType);
		if (eventName != null) {
			return eventName;
		}
		eventName = getEventName(eventType, ChangeManager.class);

		if (eventName == null) {
			// could be from the DomainObject class...
			eventName = getEventName(eventType, DomainObject.class);
		}

		eventHt.put(eventType, eventName);
		return eventName;
	}

	private String getEventName(int eventType, Class<?> c) {
		String eventName = null;
		Field[] fields = c.getFields();
		for (Field field : fields) {
			try {
				Object obj = field.get(null);
				int value = field.getInt(obj);
				if (eventType == value) {
					eventName = field.getName();
					break;
				}
			}
			catch (IllegalArgumentException e) {
				//ignore
			}
			catch (IllegalAccessException e) {
				//ignore
			}
		}
		return eventName;
	}

}
