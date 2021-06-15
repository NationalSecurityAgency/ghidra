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
package ghidra.app.plugin.core.debug.service.model;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOffer;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerSelectMappingOfferDialog extends DialogComponentProvider {

	protected enum OfferTableColumns
		implements EnumeratedTableColumn<OfferTableColumns, DebuggerMappingOffer> {
		DESCRIPTION("Description", String.class, DebuggerMappingOffer::getDescription),
		LANGUAGE("Language", LanguageID.class, DebuggerMappingOffer::getTraceLanguageID),
		COMPILER("Compiler", CompilerSpecID.class, DebuggerMappingOffer::getTraceCompilerSpecID),
		CONFIDENCE("Confidence", Integer.class, DebuggerMappingOffer::getConfidence);

		private final String header;
		private final Class<?> cls;
		private final Function<DebuggerMappingOffer, ?> getter;

		<T> OfferTableColumns(String header, Class<T> cls,
				Function<DebuggerMappingOffer, T> getter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(DebuggerMappingOffer row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}
	}

	public static class OfferTableModel
			extends DefaultEnumeratedColumnTableModel<OfferTableColumns, DebuggerMappingOffer> {

		public OfferTableModel() {
			super("Offers", OfferTableColumns.class);
		}

		@Override
		public List<OfferTableColumns> defaultSortOrder() {
			return List.of(OfferTableColumns.CONFIDENCE, OfferTableColumns.DESCRIPTION,
				OfferTableColumns.LANGUAGE, OfferTableColumns.COMPILER);
		}
	}

	public static class OfferPanel extends JPanel {
		private OfferTableModel offerTableModel = new OfferTableModel();
		private GhidraTable offerTable = new GhidraTable(offerTableModel);
		private GhidraTableFilterPanel<DebuggerMappingOffer> offerTableFilterPanel =
			new GhidraTableFilterPanel<>(offerTable, offerTableModel);

		private JScrollPane scrollPane = new JScrollPane(offerTable) {
			@Override
			public Dimension getPreferredSize() {
				Dimension pref = super.getPreferredSize();
				if (pref.width != 0) {
					pref.height = 150;
				}
				return pref;
			}
		};

		{
			setLayout(new BorderLayout());
			add(scrollPane, BorderLayout.CENTER);
			add(offerTableFilterPanel, BorderLayout.SOUTH);
		}

		public void setOffers(Collection<DebuggerMappingOffer> offers) {
			offerTableModel.clear();
			offerTableModel.addAll(offers);

			offerTable.getSelectionModel().setSelectionInterval(0, 0);
		}

		public DebuggerMappingOffer getSelectedOffer() {
			return offerTableFilterPanel.getSelectedItem();
		}
	}

	private final OfferPanel offerPanel = new OfferPanel();

	private boolean isCancelled = false;

	protected DebuggerSelectMappingOfferDialog() {
		super(DebuggerResources.AbstractRecordAction.NAME, true, false, true, false);

		populateComponents();
	}

	protected void populateComponents() {
		offerPanel.setBorder(BorderFactory.createTitledBorder(" Select Target Recorder Mapper "));

		addWorkPanel(offerPanel);
		addOKButton();
		addCancelButton();

		setDefaultButton(okButton);
		setOkEnabled(false);

		// TODO: Separate this a bit
		offerPanel.offerTable.getSelectionModel().addListSelectionListener(e -> {
			setOkEnabled(getSelectedOffer() != null);
		});
	}

	public void setOffers(Collection<DebuggerMappingOffer> offers) {
		offerPanel.setOffers(offers);
	}

	public boolean isCancelled() {
		return isCancelled;
	}

	public DebuggerMappingOffer getSelectedOffer() {
		return offerPanel.getSelectedOffer();
	}

	@Override
	protected void cancelCallback() {
		isCancelled = true;
		super.cancelCallback();
	}

	@Override
	protected void okCallback() {
		if (getSelectedOffer() != null) {
			isCancelled = false;
			close();
		}
		// Do nothing. Should be disabled anyway
	}
}
