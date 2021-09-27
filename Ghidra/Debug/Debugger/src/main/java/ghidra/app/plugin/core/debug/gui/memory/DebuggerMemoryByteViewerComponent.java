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
package ghidra.app.plugin.core.debug.gui.memory;

import java.awt.Color;
import java.awt.FontMetrics;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.plugin.core.byteviewer.*;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.colors.*;
import ghidra.app.plugin.core.debug.gui.colors.MultiSelectionBlendedLayoutBackgroundColorManager.ColoredFieldSelection;
import ghidra.app.plugin.core.format.DataFormatModel;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.annotation.AutoOptionConsumed;
import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.TraceMemoryState;

public class DebuggerMemoryByteViewerComponent extends ByteViewerComponent
		implements SelectionTranslator {

	protected class SelectionHighlightSelectionGenerator implements SelectionGenerator {
		@Override
		public void addSelections(BigInteger layoutIndex, SelectionTranslator translator,
				List<ColoredFieldSelection> selections) {
			Color selectionColor = paintContext.getSelectionColor();
			Color highlightColor = paintContext.getHighlightColor();
			selections.add(new ColoredFieldSelection(getSelection(), selectionColor));
			selections.add(new ColoredFieldSelection(getHighlight(), highlightColor));
		}
	}

	protected class TraceMemoryStateSelectionGenerator implements SelectionGenerator {
		@Override
		public void addSelections(BigInteger layoutIndex, SelectionTranslator translator,
				List<ColoredFieldSelection> selections) {
			FieldSelection lineFieldSel = new FieldSelection();
			lineFieldSel.addRange(layoutIndex, layoutIndex.add(BigInteger.ONE));

			DebuggerMemoryBytesProvider provider = panel.getProvider();
			DebuggerCoordinates coordinates = provider.current;
			if (coordinates.getView() == null) {
				return;
			}
			Trace trace = coordinates.getTrace();
			// TODO: Mimic the listing's background, or factor into common
			long snap = coordinates.getSnap();
			// TODO: Span out and cache?
			AddressSetView lineAddresses = translator.convertFieldToAddress(lineFieldSel);
			// Because UNKNOWN need not be explicitly recorded, compute it by subtracting others
			AddressSet unknown = new AddressSet(lineAddresses);
			for (AddressRange range : lineAddresses) {
				for (Entry<TraceAddressSnapRange, TraceMemoryState> entry : trace.getMemoryManager()
						.getStates(snap, range)) {
					if (entry.getValue() != TraceMemoryState.UNKNOWN) {
						unknown.delete(entry.getKey().getRange());
					}
					Color color = colorForState(entry.getValue());
					if (color == null) {
						continue;
					}
					// NOTE: Only TraceMemoryState.ERROR should reach here
					FieldSelection resultFieldSel =
						translator.convertAddressToField(entry.getKey().getRange());
					if (!resultFieldSel.isEmpty()) {
						selections.add(new ColoredFieldSelection(resultFieldSel, color));
					}
				}
			}
			if (unknownColor == null) {
				return;
			}
			for (AddressRange unk : unknown) {
				FieldSelection resultFieldSel = translator.convertAddressToField(unk);
				if (!resultFieldSel.isEmpty()) {
					selections.add(new ColoredFieldSelection(resultFieldSel, unknownColor));
				}
			}
		}
	}

	private final DebuggerMemoryBytesPanel panel;

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_ERROR_MEMORY)
	private Color errorColor;
	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_STALE_MEMORY)
	private Color unknownColor;
	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	private final List<SelectionGenerator> selectionGenerators;

	public DebuggerMemoryByteViewerComponent(DebuggerMemoryBytesPanel vpanel,
			ByteViewerLayoutModel layoutModel, DataFormatModel model, int bytesPerLine,
			FontMetrics fm) {
		super(vpanel, layoutModel, model, bytesPerLine, fm);
		// TODO: I don't care much for this reverse path
		this.panel = vpanel;

		autoOptionsWiring = AutoOptions.wireOptionsConsumed(vpanel.getProvider().getPlugin(), this);

		selectionGenerators = List.of(
			new SelectionHighlightSelectionGenerator(),
			new TraceMemoryStateSelectionGenerator(),
			vpanel.getProvider().trackingTrait.getSelectionGenerator());
		// NOTE: Cursor, being line-by-line, is done via background color model in super
	}

	protected Color colorForState(TraceMemoryState state) {
		switch (state) {
			case ERROR:
				return errorColor;
			case KNOWN:
				return null;
			case UNKNOWN:
				return unknownColor;
		}
		throw new AssertionError();
	}

	@Override
	protected LayoutBackgroundColorManager getLayoutSelectionMap(BigInteger layoutIndex) {
		Color backgroundColor = backgroundColorModel.getBackgroundColor(layoutIndex);
		boolean isBackgroundDefault =
			backgroundColorModel.getDefaultBackgroundColor().equals(backgroundColor);
		List<ColoredFieldSelection> selections = new ArrayList<>(3);
		for (SelectionGenerator sg : selectionGenerators) {
			sg.addSelections(layoutIndex, this, selections);
		}
		return MultiSelectionBlendedLayoutBackgroundColorManager.getLayoutColorMap(
			layoutIndex, selections, backgroundColor, isBackgroundDefault);
	}

	@Override
	public AddressSetView convertFieldToAddress(FieldSelection fieldSelection) {
		ProgramByteBlockSet blockSet = getBlockSet();
		if (blockSet == null) {
			return new AddressSet();
		}
		return blockSet.getAddressSet(processFieldSelection(fieldSelection));
	}

	@Override
	public FieldSelection convertAddressToField(AddressSetView addresses) {
		ProgramByteBlockSet blockSet = getBlockSet();
		if (blockSet == null) {
			return new FieldSelection();
		}
		return getFieldSelection(blockSet.getBlockSelection(addresses));
	}

	@Override
	public FieldSelection convertAddressToField(AddressRange range) {
		ProgramByteBlockSet blockSet = getBlockSet();
		if (blockSet == null) {
			return new FieldSelection();
		}
		return getFieldSelection(blockSet.getBlockSelection(range));
	}
}
