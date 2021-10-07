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
import docking.widgets.table.*;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOffer;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerSelectMappingOfferDialog extends DialogComponentProvider {

	protected enum OfferTableColumns
		implements EnumeratedTableColumn<OfferTableColumns, DebuggerMappingOffer> {
		CONFIDENCE("Confidence", Integer.class, DebuggerMappingOffer::getConfidence, SortDirection.DESCENDING),
		PROCESSOR("Processor", Processor.class, OfferTableColumns::getProcessor),
		VARIANT("Variant", String.class, OfferTableColumns::getVariant),
		SIZE("Size", Integer.class, OfferTableColumns::getSize),
		ENDIAN("Endian", Endian.class, OfferTableColumns::getEndian),
		COMPILER("Compiler", CompilerSpecID.class, DebuggerMappingOffer::getTraceCompilerSpecID);

		private static final LanguageService LANG_SERV =
			DefaultLanguageService.getLanguageService();

		private static Processor getProcessor(DebuggerMappingOffer offer) {
			try {
				return LANG_SERV.getLanguageDescription(offer.getTraceLanguageID()).getProcessor();
			}
			catch (LanguageNotFoundException e) {
				return Processor.findOrPossiblyCreateProcessor("Not Found");
			}
		}

		private static String getVariant(DebuggerMappingOffer offer) {
			try {
				return LANG_SERV.getLanguageDescription(offer.getTraceLanguageID()).getVariant();
			}
			catch (LanguageNotFoundException e) {
				return "???";
			}
		}

		private static int getSize(DebuggerMappingOffer offer) {
			try {
				return LANG_SERV.getLanguageDescription(offer.getTraceLanguageID()).getSize();
			}
			catch (LanguageNotFoundException e) {
				return 0;
			}
		}

		private static Endian getEndian(DebuggerMappingOffer offer) {
			try {
				return LANG_SERV.getLanguageDescription(offer.getTraceLanguageID()).getEndian();
			}
			catch (LanguageNotFoundException e) {
				return null;
			}
		}

		private final String header;
		private final Class<?> cls;
		private final Function<DebuggerMappingOffer, ?> getter;
		private final SortDirection sortDir;

		<T> OfferTableColumns(String header, Class<T> cls,
				Function<DebuggerMappingOffer, T> getter, SortDirection sortDir) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.sortDir = sortDir;
		}

		<T> OfferTableColumns(String header, Class<T> cls,
				Function<DebuggerMappingOffer, T> getter) {
			this(header, cls, getter, SortDirection.ASCENDING);
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

		@Override
		public SortDirection defaultSortDirection() {
			return sortDir;
		}
	}

	public static class OfferTableModel
			extends DefaultEnumeratedColumnTableModel<OfferTableColumns, DebuggerMappingOffer> {

		public OfferTableModel() {
			super("Offers", OfferTableColumns.class);
		}

		@Override
		public List<OfferTableColumns> defaultSortOrder() {
			return List.of(OfferTableColumns.CONFIDENCE, OfferTableColumns.PROCESSOR,
				OfferTableColumns.VARIANT, OfferTableColumns.COMPILER);
		}
	}

	public static class OfferPanel extends JPanel {
		private final OfferTableModel offerTableModel = new OfferTableModel();
		private final GhidraTable offerTable = new GhidraTable(offerTableModel);
		private final GhidraTableFilterPanel<DebuggerMappingOffer> offerTableFilterPanel =
			new GhidraTableFilterPanel<>(offerTable, offerTableModel);
		private final JLabel descLabel = new JLabel();
		private final JCheckBox overrideCheckBox = new JCheckBox("Show Only Recommended Offers");

		private final JScrollPane scrollPane = new JScrollPane(offerTable) {
			@Override
			public Dimension getPreferredSize() {
				Dimension pref = super.getPreferredSize();
				if (pref.width != 0) {
					pref.height = 150;
				}
				return pref;
			}
		};
		private final TableFilter<DebuggerMappingOffer> filterRecommended = new TableFilter<>() {
			@Override
			public boolean acceptsRow(DebuggerMappingOffer offer) {
				return !offer.isOverride();
			}

			@Override
			public boolean isSubFilterOf(TableFilter<?> tableFilter) {
				return false;
			}
		};

		private LanguageID preferredLangID;
		private CompilerSpecID preferredCsID;

		{
			JPanel descPanel = new JPanel(new BorderLayout());
			descPanel.setBorder(BorderFactory.createTitledBorder("Description"));
			descPanel.add(descLabel, BorderLayout.CENTER);

			JPanel nested1 = new JPanel(new BorderLayout());
			nested1.add(scrollPane, BorderLayout.CENTER);
			nested1.add(offerTableFilterPanel, BorderLayout.SOUTH);

			JPanel nested2 = new JPanel(new BorderLayout());
			nested2.add(nested1, BorderLayout.CENTER);
			nested2.add(descPanel, BorderLayout.SOUTH);

			setLayout(new BorderLayout());
			add(nested2, BorderLayout.CENTER);
			add(overrideCheckBox, BorderLayout.SOUTH);

			setFilterRecommended(true);
			offerTable.getSelectionModel().addListSelectionListener(e -> {
				DebuggerMappingOffer offer = getSelectedOffer();
				descLabel.setText(offer == null ? "" : offer.getDescription());
			});

			overrideCheckBox.addActionListener(evt -> {
				setFilterRecommended(overrideCheckBox.isSelected());
			});
		}

		public void setPreferredIDs(LanguageID langID, CompilerSpecID csID) {
			this.preferredLangID = langID;
			this.preferredCsID = csID;
		}

		public void setOffers(Collection<DebuggerMappingOffer> offers) {
			offerTableModel.clear();
			offerTableModel.addAll(offers);

			selectPreferred();
		}

		private void selectPreferred() {
			// As sorted and filtered, pick the first matching offer
			// NB. It should never be one or the other. Always both or none.
			RowObjectFilterModel<DebuggerMappingOffer> model =
				offerTableFilterPanel.getTableFilterModel();
			int count = model.getRowCount();
			if (preferredLangID != null && preferredCsID != null) {
				for (int i = 0; i < count; i++) {
					DebuggerMappingOffer offer = model.getRowObject(i);
					if (offer.getTraceLanguageID().equals(preferredLangID) &&
						offer.getTraceCompilerSpecID().equals(preferredCsID)) {
						offerTable.getSelectionModel().setSelectionInterval(i, i);
						return;
					}
				}
			}
			// Fall back to first offer; disregard preference
			if (model.getRowCount() > 0) {
				offerTable.getSelectionModel().setSelectionInterval(0, 0);
			}
		}

		public void setFilterRecommended(boolean recommendedOnly) {
			boolean hasSelection = offerTableFilterPanel.getSelectedItem() != null;
			overrideCheckBox.setSelected(recommendedOnly);
			offerTableFilterPanel.setSecondaryFilter(recommendedOnly ? filterRecommended : null);
			if (!hasSelection) {
				selectPreferred();
			}
		}

		public void setSelectedOffer(DebuggerMappingOffer offer) {
			offerTableFilterPanel.setSelectedItem(offer);
		}

		public DebuggerMappingOffer getSelectedOffer() {
			return offerTableFilterPanel.getSelectedItem();
		}

		// For tests
		public List<DebuggerMappingOffer> getDisplayedOffers() {
			return List.copyOf(offerTableFilterPanel.getTableFilterModel().getModelData());
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

	/**
	 * Set the preferred language and compiler spec IDs, typically from the current program.
	 * 
	 * <p>
	 * This must be called before {@link #setOffers(Collection)}.
	 * 
	 * @param langID the preferred language
	 * @param csID the preferred compiler spec (ABI)
	 */
	public void setPreferredIDs(LanguageID langID, CompilerSpecID csID) {
		offerPanel.setPreferredIDs(langID, csID);
	}

	public void setOffers(Collection<DebuggerMappingOffer> offers) {
		offerPanel.setOffers(offers);
	}

	public boolean isCancelled() {
		return isCancelled;
	}

	public void setSelectedOffer(DebuggerMappingOffer offer) {
		offerPanel.setSelectedOffer(offer);
	}

	public DebuggerMappingOffer getSelectedOffer() {
		return offerPanel.getSelectedOffer();
	}

	// For tests
	protected List<DebuggerMappingOffer> getDisplayedOffers() {
		return offerPanel.getDisplayedOffers();
	}

	protected void setFilterRecommended(boolean recommendedOnly) {
		offerPanel.setFilterRecommended(recommendedOnly);
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
