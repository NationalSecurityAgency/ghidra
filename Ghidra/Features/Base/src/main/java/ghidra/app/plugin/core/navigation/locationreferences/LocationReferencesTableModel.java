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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.awt.Color;
import java.awt.Component;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.AddressPreviewTableModel;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;

/**
 * A table model that shows the same contents as the {@link AddressPreviewTableModel}, but will
 * also add a references table column when the underlying data contains references.  This model
 * uses data provided by a {@link LocationDescriptor}, which is contained by the given
 * {@link LocationReferencesProvider}.
 * <p>
 * This model also adds the functionality for clients to know when the model has finished loading
 * and it also allows users to reload the data.
 */
class LocationReferencesTableModel extends AddressBasedTableModel<LocationReference> {

	private LocationReferencesProvider provider;
	private boolean initialized = false;
	private boolean performFullReload = false;

	LocationReferencesTableModel(LocationReferencesProvider locationReferencesProvider) {
		super("References", locationReferencesProvider.getTool(),
			locationReferencesProvider.getProgram(), null, true);
		this.provider = locationReferencesProvider;

		addTableColumn(new ContextTableColumn());
	}

	@Override
	protected void doLoad(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {

		LocationDescriptor locationDescriptor = provider.getLocationDescriptor();

		// do this here so that the search is always up-to-date with the options, even if
		// the descriptor is cached
		locationDescriptor.setUseDynamicSearching(provider.useDynamicDataTypeSearching());

		locationDescriptor.getReferences(accumulator, monitor, performFullReload);
		initialized = true;
		performFullReload = false; // no need to perform full reloads unless explicitly set to
	}

	private Collection<Address> toAddresses(Iterable<LocationReference> references) {
		Set<Address> set = new HashSet<>();
		for (LocationReference locationReference : references) {
			set.add(locationReference.getLocationOfUse());
		}
		return set;
	}

	Collection<Address> getReferenceAddresses() {
		return toAddresses(getAllData());
	}

	boolean isInitialized() {
		return initialized;
	}

	// overridden to change initialization state, since clients need to know when this model
	// is finished loading
	@Override
	public void reload() {
		initialized = false;
		super.reload();
	}

	// this reload will signal the underlying model to perform a full reload of its data,
	// rather than just using the cached data
	void fullReload() {
		performFullReload = true;
		reload();
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getLocationOfUse();
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {

		LocationReference ref = getRowObject(row);
		ProgramLocation location = ref.getProgramLocation();
		if (location != null) {
			return location;
		}

		return super.getProgramLocation(row, column);
	}

//==================================================================================================
//  Inner Classes
//==================================================================================================

	private class ContextTableColumn
			extends
			AbstractProgramBasedDynamicTableColumn<LocationReference, LocationReference> {

		private ContextCellRenderer renderer = new ContextCellRenderer();

		@Override
		public LocationReference getValue(LocationReference rowObject, Settings settings, Program p,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject;
		}

		@Override
		public String getColumnName() {
			return "Context";
		}

		@Override
		public String getColumnDescription() {
			return "<html>Provides information about the references, such as<br>" +
				"the reference type (for applied references) or the context<br>" +
				"of use for discovered references";
		}

		@Override
		public GColumnRenderer<LocationReference> getColumnRenderer() {
			return renderer;
		}
	}

	private class ContextCellRenderer extends AbstractGhidraColumnRenderer<LocationReference> {

		private static final String OFFCUT_STRING = "<< OFFCUT >>";

		{
			setHTMLRenderingEnabled(true);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			// initialize
			super.getTableCellRendererComponent(data);

			LocationReference rowObject = (LocationReference) data.getRowObject();
			String refTypeString = getRefTypeString(rowObject);
			if (refTypeString != null) {
				setText(refTypeString);
				return this;
			}

			// when the row object does not represent an applied reference, then it may have context
			LocationReferenceContext context = rowObject.getContext();
			String text = context.getBoldMatchingText();
			setText(text);
			return this;
		}

		private String getRefTypeString(LocationReference rowObject) {
			String refType = rowObject.getRefTypeString();
			if (!StringUtils.isBlank(refType)) {
				String trailingText = "";
				if (rowObject.isOffcutReference()) {
					setForeground(Color.RED);
					trailingText = OFFCUT_STRING;
				}
				return refType + trailingText;
			}
			return null;
		}

		@Override
		public String getFilterString(LocationReference rowObject, Settings settings) {
			String refTypeString = getRefTypeString(rowObject);
			if (refTypeString != null) {
				return refTypeString;
			}

			LocationReferenceContext context = rowObject.getContext();
			return context.getPlainText();
		}
	}
}
