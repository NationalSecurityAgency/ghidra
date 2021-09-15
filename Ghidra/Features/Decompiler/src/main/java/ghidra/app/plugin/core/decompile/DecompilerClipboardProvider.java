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
package ghidra.app.plugin.core.decompile;

import java.awt.FontMetrics;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.services.ClipboardContentProviderService;
import ghidra.app.util.ByteCopier;
import ghidra.app.util.ClipboardType;
import ghidra.util.task.TaskMonitor;

public class DecompilerClipboardProvider extends ByteCopier
		implements ClipboardContentProviderService {

	private static final PaintContext PAINT_CONTEXT = new PaintContext();
	private static final ClipboardType TEXT_TYPE =
		new ClipboardType(DataFlavor.stringFlavor, "Text");
	private static final List<ClipboardType> COPY_TYPES = new LinkedList<>();

	static {
		COPY_TYPES.add(TEXT_TYPE);
	}

	private DecompilerProvider provider;
	private FieldSelection selection;

	private boolean copyFromSelectionEnabled;
	private Set<ChangeListener> listeners = new CopyOnWriteArraySet<>();
	private int spaceCharWidthInPixels = 7;

	public DecompilerClipboardProvider(DecompilePlugin plugin, DecompilerProvider provider) {
		this.provider = provider;
		this.tool = plugin.getTool();
		PAINT_CONTEXT.setTextCopying(true);
	}

	@Override
	public void addChangeListener(ChangeListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	private void notifyStateChanged() {
		ChangeEvent event = new ChangeEvent(this);
		for (ChangeListener listener : listeners) {
			listener.stateChanged(event);
		}
	}

	@Override
	public Transferable copy(TaskMonitor monitor) {
		if (!copyFromSelectionEnabled) {
			return createStringTransferable(getCursorText());
		}

		return copyText(monitor);
	}

	private String getCursorText() {
		DecompilerPanel panel = provider.getDecompilerPanel();
		ClangToken token = panel.getTokenAtCursor();
		if (token == null) {
			return null;
		}

		String text = token.getText();
		return text;
	}

	@Override
	public List<ClipboardType> getCurrentCopyTypes() {
		if (copyFromSelectionEnabled) {
			return COPY_TYPES;
		}
		return EMPTY_LIST;
	}

	public List<ClipboardType> getCurrentPasteTypes(Transferable t) {
		return null;
	}

	@Override
	public Transferable copySpecial(ClipboardType copyType, TaskMonitor monitor) {
		if (copyType == TEXT_TYPE) {
			return copyText(monitor);
		}

		return null;
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return context.getComponentProvider() == provider;
	}

	public void selectionChanged(FieldSelection sel) {
		this.selection = sel;
		copyFromSelectionEnabled = (selection != null && selection.getNumRanges() > 0);
		notifyStateChanged();
	}

	@Override
	public ComponentProvider getComponentProvider() {
		return provider;
	}

	@Override
	public boolean enableCopy() {
		return true;
	}

	@Override
	public boolean enableCopySpecial() {
		return false;
	}

	@Override
	public boolean canCopy() {
		return copyFromSelectionEnabled || !StringUtils.isBlank(getCursorText());
	}

	@Override
	public boolean canCopySpecial() {
		return false;
	}

	private Transferable copyText(TaskMonitor monitor) {
		return createStringTransferable(getText());
	}

	private String getText() {
		StringBuilder buffer = new StringBuilder();
		int numRanges = selection.getNumRanges();
		for (int i = 0; i < numRanges; i++) {
			appendText(buffer, selection.getFieldRange(i));
		}
		return buffer.toString();
	}

	private void appendText(StringBuilder buffer, FieldRange fieldRange) {
		int startIndex = fieldRange.getStart().getIndex().intValue();
		int endIndex = fieldRange.getEnd().getIndex().intValue();
		if (startIndex == endIndex) { // single line selection (don't include padding)
			appendTextSingleLine(buffer, startIndex, selection.intersect(startIndex));
			return;
		}

		appendText(buffer, startIndex, selection.intersect(startIndex));
		for (int line = startIndex + 1; line <= endIndex; line++) {
			buffer.append('\n');
			appendText(buffer, line, selection.intersect(line));
		}
	}

	private void appendText(StringBuilder buffer, int lineNumber,
			FieldSelection singleLineSelection) {
		if (singleLineSelection.isEmpty()) {
			return;
		}
		FieldRange fieldRange = singleLineSelection.getFieldRange(0);
		int startColumn = fieldRange.getStart().getCol();
		int endColumn = Integer.MAX_VALUE;
		int startRow = fieldRange.getStart().getRow();
		int endRow = Integer.MAX_VALUE;
		int startIndex = fieldRange.getStart().getIndex().intValue();
		int endIndex = fieldRange.getEnd().getIndex().intValue();
		if (startIndex == endIndex) {
			endColumn = fieldRange.getEnd().getCol();
			endRow = fieldRange.getEnd().getRow();
		}

		LayoutModel model = provider.getDecompilerPanel().getLayoutModel();
		Layout layout = model.getLayout(BigInteger.valueOf(lineNumber));
		ClangTextField field = (ClangTextField) layout.getField(0);
		int numSpaces = (field.getStartX() - field.getLineNumberWidth()) / spaceCharWidthInPixels;
		for (int i = 0; i < numSpaces; i++) {
			buffer.append(' ');
		}

		int startPos = field.screenLocationToTextOffset(startRow, startColumn);
		int endPos = field.screenLocationToTextOffset(endRow, endColumn);
		for (int i = 0; i < startPos; i++) {
			buffer.append(' ');
		}
		if (startPos >= 0 && endPos >= startPos) {
			buffer.append(field.getText().substring(startPos, endPos));
		}
	}

	private void appendTextSingleLine(StringBuilder buffer, int lineNumber,
			FieldSelection singleLineSelection) {
		if (singleLineSelection.isEmpty()) {
			return;
		}
		FieldRange fieldRange = singleLineSelection.getFieldRange(0);
		int startColumn = fieldRange.getStart().getCol();
		int endColumn = fieldRange.getEnd().getCol();
		int startRow = fieldRange.getStart().getRow();
		int endRow = fieldRange.getEnd().getRow();

		LayoutModel model = provider.getDecompilerPanel().getLayoutModel();
		Layout layout = model.getLayout(BigInteger.valueOf(lineNumber));
		ClangTextField field = (ClangTextField) layout.getField(0);

		int startPos = field.screenLocationToTextOffset(startRow, startColumn);
		int endPos = field.screenLocationToTextOffset(endRow, endColumn);

		if (startPos >= 0 && endPos >= startPos) {
			buffer.append(field.getText().substring(startPos, endPos));
		}
	}

//==================================================================================================
// Unsupported Operations
//==================================================================================================

	@Override
	public boolean enablePaste() {
		return false;
	}

	@Override
	public boolean canPaste(DataFlavor[] availableFlavors) {
		return false;
	}

	@Override
	public boolean paste(Transferable pasteData) {
		return false;
	}

	public boolean pasteSpecial(Transferable pasteData, ClipboardType pasteType) {
		return false;
	}

	@Override
	public void lostOwnership(Transferable transferable) {
		// no-op
	}

	public void setFontMetrics(FontMetrics metrics) {
		spaceCharWidthInPixels = metrics.charWidth(' ');
	}
}
