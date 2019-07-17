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
package ghidra.feature.vt.gui.provider.matchtable;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.JCheckBox;

import docking.widgets.checkbox.GCheckBox;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.filters.CheckBoxBasedAncillaryFilter;
import ghidra.feature.vt.gui.filters.CheckBoxInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * This filter allows through any match that has a source *or* destination symbol type matches
 * the selected source types.
 */
public class SymbolTypeFilter extends CheckBoxBasedAncillaryFilter<VTMatch> {

	public SymbolTypeFilter() {
		super("Symbol Type");
	}

	@Override
	protected void createCheckBoxInfos() {
		ItemListener listener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				fireStatusChanged(getFilterStatus());
			}
		};

		SourceType[] values = SourceType.values();
		for (SourceType type : values) {
			GCheckBox checkBox = new GCheckBox(type.getDisplayString(), true);
			checkBox.addItemListener(listener);
			CheckBoxInfo<VTMatch> info = new SymbolTypeCheckBoxInfo(checkBox, type);
			checkBoxInfos.add(info);
		}

		GCheckBox nullSymbolCheckbox = new GCheckBox("<No Symbol>", true);
		nullSymbolCheckbox.addItemListener(listener);
		checkBoxInfos.add(new NullSymbolCheckBoxInfo(nullSymbolCheckbox));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class SymbolTypeCheckBoxInfo extends CheckBoxInfo<VTMatch> {

		private SourceType sourceType;

		public SymbolTypeCheckBoxInfo(JCheckBox checkBox, SourceType sourceType) {
			super(checkBox);
			this.sourceType = sourceType;
		}

		@Override
		public boolean matchesStatus(VTMatch match) {
			if (!isSelected()) {
				return false;
			}

			//
			// Our filter matches on two different columns
			//

			VTAssociation association = match.getAssociation();
			VTSession session = association.getSession();

			Address sourceAddress = association.getSourceAddress();
			Program sourceProgram = session.getSourceProgram();
			SymbolTable sourceSymbolTable = sourceProgram.getSymbolTable();
			Symbol sourceSymbol = sourceSymbolTable.getPrimarySymbol(sourceAddress);
			if (sourceSymbol != null) {
				SourceType sourceSymbolSourceType = sourceSymbol.getSource();
				if (sourceSymbolSourceType.equals(sourceType)) {
					return true;
				}
			}

			Address destinationAddress = association.getDestinationAddress();
			Program destinationProgram = session.getDestinationProgram();
			SymbolTable destinationSymbolTable = destinationProgram.getSymbolTable();
			Symbol destinationSymbol = destinationSymbolTable.getPrimarySymbol(destinationAddress);
			if (destinationSymbol != null) {
				SourceType destinationSymbolSourceType = destinationSymbol.getSource();
				return destinationSymbolSourceType.equals(sourceType);
			}
			return false;
		}
	}

	private class NullSymbolCheckBoxInfo extends CheckBoxInfo<VTMatch> {

		NullSymbolCheckBoxInfo(JCheckBox checkBox) {
			super(checkBox);
		}

		@Override
		public boolean matchesStatus(VTMatch match) {
			if (!isSelected()) {
				return false;
			}

			//
			// Our filter matches on two different columns
			//

			VTAssociation association = match.getAssociation();
			VTSession session = association.getSession();

			Address sourceAddress = association.getSourceAddress();
			Program sourceProgram = session.getSourceProgram();
			SymbolTable sourceSymbolTable = sourceProgram.getSymbolTable();
			Symbol sourceSymbol = sourceSymbolTable.getPrimarySymbol(sourceAddress);
			if (sourceSymbol == null) {
				return true;
			}

			Address destinationAddress = association.getDestinationAddress();
			Program destinationProgram = session.getDestinationProgram();
			SymbolTable destinationSymbolTable = destinationProgram.getSymbolTable();
			Symbol destinationSymbol = destinationSymbolTable.getPrimarySymbol(destinationAddress);
			return (destinationSymbol == null);
		}
	}
}
