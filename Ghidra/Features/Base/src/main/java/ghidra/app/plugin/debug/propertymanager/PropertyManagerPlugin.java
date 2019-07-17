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
package ghidra.app.plugin.debug.propertymanager;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.MarkerService;
import ghidra.app.services.MarkerSet;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ImageIcon;
import javax.swing.Timer;

import resources.ResourceManager;


/**
 * PropertyManagerPlugin
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.TESTING,
	shortDescription = "Show Markers for Properties",
	description = "This plugin shows a list of properties in the program."+
			" For each property selected, navigation markers are displayed to indicate "+
			"where the property exists.",
	servicesRequired = { MarkerService.class }
)
//@formatter:on
public class PropertyManagerPlugin extends ProgramPlugin implements DomainObjectListener {

	private static final ImageIcon propIcon = ResourceManager.loadImage("images/searchm_pink.gif");

	final static String DISPLAY_ACTION_NAME = "Display Property Viewer";
	final static String PROPERTY_MARKER_NAME = "Property Locations";

	private PropertyManagerProvider propertyViewProvider;
    private MarkerService markerService;
    private MarkerSet searchMarks;
    private Timer updateTimer;

	public PropertyManagerPlugin(PluginTool tool) {
		super(tool, false, true);

		propertyViewProvider = new PropertyManagerProvider(this);
	}

	/**
	 * @see ghidra.framework.plugintool.Plugin#init()
	 */
	@Override
    protected void init() {

		markerService = tool.getService(MarkerService.class);


		updateTimer = new Timer(500, new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (propertyViewProvider != null && propertyViewProvider.isVisible()) {
					propertyViewProvider.refresh();
				}
			}
		});
		updateTimer.setRepeats(false);
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.framework.model.DomainObjectListener#domainObjectChanged(ghidra.framework.model.DomainObjectChangedEvent)
	 */
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (propertyViewProvider == null || !propertyViewProvider.isVisible()) {
			return;
		}

		boolean affectedByChange = false;
		int cnt = ev.numRecords();
		for (int i = 0; i < cnt; i++) {

			DomainObjectChangeRecord record = ev.getChangeRecord(i);

			int eventType = record.getEventType();
			if (eventType == DomainObject.DO_OBJECT_RESTORED ||
				eventType == ChangeManager.DOCR_MEMORY_BLOCK_MOVED ||
				eventType == ChangeManager.DOCR_MEMORY_BLOCK_REMOVED ||
				eventType == ChangeManager.DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED)
			{
				affectedByChange = true;
				break;
			}
			if (!(record instanceof CodeUnitPropertyChangeRecord)) {
				continue;
			}

			if (currentSelection == null || currentSelection.isEmpty()) {
				affectedByChange = true;
				break;
			}

			CodeUnitPropertyChangeRecord pcr = (CodeUnitPropertyChangeRecord)record;
			Address addr = pcr.getAddress();
			if (addr != null) {
				if (currentSelection.contains(addr)) {
					affectedByChange = true;
					break;
				}
			}
			else {
				addr = pcr.getStartAddress();
				Address endAddr = pcr.getEndAddress();
				if (addr != null && endAddr != null && currentSelection.intersects(addr, endAddr)) {
					affectedByChange = true;
					break;
				}
			}
		}

		if (affectedByChange) {
			updateTimer.restart();
		}
    }

	@Override
    protected void programActivated(Program program) {
		program.addListener(this);
		propertyViewProvider.programActivated(program);
	}

	@Override
    protected void programDeactivated(Program program) {
		disposeSearchMarks(program);
		if (program != null) {
			program.removeListener(this);
		}
		propertyViewProvider.programDeactivated();
	}

    @Override
    protected void selectionChanged(ProgramSelection sel) {
    	if (propertyViewProvider != null && propertyViewProvider.isVisible()) {
    		updateTimer.restart();
    	}
    }

	/**
	 * Initialize search marker manager
	 */
	MarkerSet getSearchMarks() {
		if (searchMarks == null && currentProgram != null) {
			searchMarks = markerService.createPointMarker(PROPERTY_MARKER_NAME,
			    "Locations where properties are set", currentProgram,
			    MarkerService.PROPERTY_PRIORITY, true, true, false, Color.pink, propIcon);
		}
		return searchMarks;
	}

	/**
	 * Dispose search marker manager
	 */
	void disposeSearchMarks() {
		disposeSearchMarks( currentProgram );
	}

	private void disposeSearchMarks( Program program ) {
	    if (searchMarks != null && program != null) {
            markerService.removeMarker(searchMarks, program);
            searchMarks = null;
        }
	}

	void clearSearchMarks() {
	    if ( searchMarks != null ) {
	        searchMarks.clearAll();
	    }
	}

	/**
	 * @see ghidra.framework.plugintool.Plugin#dispose()
	 */
	@Override
    public void dispose() {
		super.dispose();

        disposeSearchMarks();

        if (currentProgram != null) {
        	currentProgram.removeListener(this);
        }

		if (propertyViewProvider != null) {
			propertyViewProvider.dispose();
			propertyViewProvider = null;
		}

	}

	PropertyManagerProvider getPropertyViewProvider() {
		return propertyViewProvider;
	}

	AddressSetView getCurrentSelection() {
		return currentSelection;
	}

}
