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
package ghidra.app.plugin.core.clipboard;

import java.awt.Rectangle;
import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.dnd.GenericDataFlavor;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.internal.*;
import generic.text.TextLayoutGraphics;
import ghidra.app.cmd.comments.CodeUnitInfoPasteCmd;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.app.services.ClipboardContentProviderService;
import ghidra.app.util.*;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

public class CodeBrowserClipboardProvider extends ByteCopier
		implements ClipboardContentProviderService {

	protected static final PaintContext PAINT_CONTEXT = new PaintContext();
	private static int[] COMMENT_TYPES = CommentTypes.getTypes();

	public static final ClipboardType ADDRESS_TEXT_TYPE =
		new ClipboardType(DataFlavor.stringFlavor, "Address");
	public static final ClipboardType CODE_TEXT_TYPE =
		new ClipboardType(DataFlavor.stringFlavor, "Formatted Code");
	public static final ClipboardType LABELS_COMMENTS_TYPE =
		new ClipboardType(CodeUnitInfoTransferable.localDataTypeFlavor, "Labels and Comments");
	public static final ClipboardType LABELS_TYPE =
		new ClipboardType(CodeUnitInfoTransferable.localDataTypeFlavor, "Labels");
	public static final ClipboardType COMMENTS_TYPE =
		new ClipboardType(CodeUnitInfoTransferable.localDataTypeFlavor, "Comments");

	private static final List<ClipboardType> COPY_TYPES = createCopyTypesList();

	private static List<ClipboardType> createCopyTypesList() {
		List<ClipboardType> list = new LinkedList<>();

		list.add(CODE_TEXT_TYPE);
		list.add(LABELS_COMMENTS_TYPE);
		list.add(LABELS_TYPE);
		list.add(COMMENTS_TYPE);
		list.add(BYTE_STRING_TYPE);
		list.add(BYTE_STRING_NO_SPACE_TYPE);
		list.add(PYTHON_BYTE_STRING_TYPE);
		list.add(PYTHON_LIST_TYPE);
		list.add(CPP_BYTE_ARRAY_TYPE);
		list.add(ADDRESS_TEXT_TYPE);

		return list;
	}

	protected boolean copyFromSelectionEnabled;
	protected ComponentProvider componentProvider;
	private ListingModel model;

	private Set<ChangeListener> listeners = new CopyOnWriteArraySet<>();
	private String stringContent;

	public CodeBrowserClipboardProvider(PluginTool tool, ComponentProvider codeViewerProvider) {
		this.tool = tool;
		this.componentProvider = codeViewerProvider;

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
		if (stringContent != null) {
			return createStringTransferable(stringContent);
		}

		if (copyFromSelectionEnabled) {
			return copyCode(monitor);
		}

		return copyFromCurrentLocation();
	}

	@Override
	public boolean paste(Transferable pasteData) {
		try {
			DataFlavor[] flavors = pasteData.getTransferDataFlavors();
			for (DataFlavor element : flavors) {
				if (element.equals(LABELS_COMMENTS_TYPE.getFlavor())) {
					return pasteLabelsComments(pasteData, true, true);
				}
				else if (element.equals(LABELS_TYPE.getFlavor())) {
					return pasteLabelsComments(pasteData, true, false);
				}
				else if (element.equals(COMMENTS_TYPE.getFlavor())) {
					return pasteLabelsComments(pasteData, false, true);
				}
				else if (element.equals(LabelStringTransferable.labelStringFlavor)) {
					return pasteLabelString(pasteData);
				}
				else if (element.equals(NonLabelStringTransferable.nonLabelStringFlavor)) {
					return pasteNonLabelString(pasteData);
				}
			}

			if (super.pasteBytes(pasteData)) {
				return true;
			}

			tool.setStatusInfo("Paste failed: unsupported data type", true);
		}
		catch (Exception e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}

			Msg.error(this, "Unexpected Exception: " + msg, e);
			tool.setStatusInfo("Paste failed: " + msg, true);
		}
		return false;
	}

	@Override
	public List<ClipboardType> getCurrentCopyTypes() {
		return COPY_TYPES;
	}

	@Override
	public Transferable copySpecial(ClipboardType copyType, TaskMonitor monitor) {

		if (copyType == ADDRESS_TEXT_TYPE) {
			return copyAddress();
		}
		else if (copyType == CODE_TEXT_TYPE) {
			return copyCode(monitor);
		}
		else if (copyType == LABELS_COMMENTS_TYPE) {
			return copyLabelsComments(true, true);
		}
		else if (copyType == LABELS_TYPE) {
			return copyLabelsComments(true, false);
		}
		else if (copyType == COMMENTS_TYPE) {
			return copyLabelsComments(false, true);
		}

		return copyBytes(copyType, monitor);
	}

	public void setStringContent(String text) {
		this.stringContent = text;
	}

	public String getStringContent() {
		return stringContent;
	}

	public void setLocation(ProgramLocation location) {
		currentLocation = location;
	}

	public void setSelection(ProgramSelection selection) {
		currentSelection = selection;
		copyFromSelectionEnabled = selection != null && !selection.isEmpty();
		notifyStateChanged();
	}

	public void setProgram(Program p) {
		currentProgram = p;
		currentLocation = null;
		currentSelection = null;
	}

	public void setListingLayoutModel(ListingModel model) {
		this.model = model;
	}

	protected ListingModel getListingModel() {
		return model;
	}

	private Transferable copyFromCurrentLocation() {

		Address address = currentLocation.getAddress();
		if (currentLocation instanceof AddressFieldLocation) {
			return new NonLabelStringTransferable(address.toString());
		}
		else if (currentLocation instanceof LabelFieldLocation) {
			LabelFieldLocation labelFieldLocation = (LabelFieldLocation) currentLocation;
			return new LabelStringTransferable(labelFieldLocation.getName());
		}
		else if (currentLocation instanceof FunctionNameFieldLocation) {
			FunctionNameFieldLocation functionNameLocation =
				(FunctionNameFieldLocation) currentLocation;
			return new LabelStringTransferable(functionNameLocation.getFunctionName());
		}
		else if (currentLocation instanceof CommentFieldLocation) {
			CommentFieldLocation commentFieldLocation = (CommentFieldLocation) currentLocation;
			String[] comment = commentFieldLocation.getComment();
			return new NonLabelStringTransferable(comment);
		}
		else if (currentLocation instanceof BytesFieldLocation) {
			// bytes are special--let them get copied and pasted as normal
			return copyByteString(address);
		}
		else if (currentLocation instanceof OperandFieldLocation) {
			return getOperandLocationTransferable((OperandFieldLocation) currentLocation);
		}
		else if (currentLocation instanceof MnemonicFieldLocation) {
			MnemonicFieldLocation location = (MnemonicFieldLocation) currentLocation;
			return new NonLabelStringTransferable(location.getMnemonic());
		}
		else if (currentLocation instanceof VariableLocation) {
			VariableLocation variableLocation = (VariableLocation) currentLocation;
			Variable variable = variableLocation.getVariable();
			return new LabelStringTransferable(variable.getName());
		}

		return null;
	}

	private Transferable getOperandLocationTransferable(OperandFieldLocation location) {

		int opIndex = location.getOperandIndex();
		Listing listing = currentProgram.getListing();
		Instruction instruction = listing.getInstructionAt(location.getAddress());
		if (instruction == null) {
			// just copy the representation--WYSIWIG
			return new NonLabelStringTransferable(location.getOperandRepresentation());
		}

		Reference reference = instruction.getPrimaryReference(opIndex);
		if (reference == null) {
			// just copy the representation--WYSIWIG
			return new NonLabelStringTransferable(location.getOperandRepresentation());
		}

		Variable variable = currentProgram.getReferenceManager().getReferencedVariable(reference);
		if (variable != null) {
			return new LabelStringTransferable(variable.getName());
		}

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Symbol symbol = symbolTable.getSymbol(reference);
		if (symbol != null) {
			return new LabelStringTransferable(symbol.getName());
		}

		// just copy the representation--WYSIWIG
		return new NonLabelStringTransferable(location.getOperandRepresentation());
	}

	private Transferable copyAddress() {

		AddressSetView addressSet = getSelectedAddresses();
		AddressIterator it = addressSet.getAddresses(true);
		String joined = StringUtils.join((Iterator<Address>) it, "\n");
		return createStringTransferable(joined);
	}

	protected Transferable copyCode(TaskMonitor monitor) {

		AddressSetView addressSet = getSelectedAddresses();
		try {
			TextLayoutGraphics g = new TextLayoutGraphics();

			Rectangle rect = new Rectangle(Integer.MAX_VALUE, Integer.MAX_VALUE);

			AddressRangeIterator rangeItr = addressSet.getAddressRanges();
			while (rangeItr.hasNext()) {
				AddressRange curRange = rangeItr.next();
				Address curAddress = curRange.getMinAddress();
				Address maxAddress = curRange.getMaxAddress();

				// getAddressAfter(curAddress) returns null in certain situations
				while (curAddress != null && curAddress.compareTo(maxAddress) <= 0) {
					if (monitor.isCancelled()) {
						break;
					}

					//Add the layout for the present address
					Layout layout = getListingModel().getLayout(curAddress, false);
					if (layout != null) {
						LayoutBackgroundColorManager layoutColorMap =
							new EmptyLayoutBackgroundColorManager(PAINT_CONTEXT.getBackground());
						layout.paint(null, g, PAINT_CONTEXT, rect, layoutColorMap, null);
						g.flush();
					}
					// may be null
					curAddress = getListingModel().getAddressAfter(curAddress);
				}
			}

			return createStringTransferable(g.getBuffer().toString());
		}
		catch (Exception e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}

			String message = "Copy failed: " + msg;
			Msg.error(this, message, e);
			tool.setStatusInfo(message, true);
		}

		return null;
	}

	private Transferable copyByteString(Address address) {
		AddressSet set = new AddressSet(address);
		return createStringTransferable(copyBytesAsString(set, false, TaskMonitor.DUMMY));
	}

	private CodeUnitInfoTransferable copyLabelsComments(boolean copyLabels, boolean copyComments) {

		AddressSetView addressSet = getSelectedAddresses();
		List<CodeUnitInfo> list = new ArrayList<>();
		Address startAddr = addressSet.getMinAddress();
		getCodeUnitInfo(addressSet, startAddr, list, copyLabels, copyComments);
		return new CodeUnitInfoTransferable(list);
	}

	private boolean pasteLabelsComments(Transferable pasteData, boolean pasteLabels,
			boolean pasteComments) {
		try {
			List<?> list =
				(List<?>) pasteData.getTransferData(CodeUnitInfoTransferable.localDataTypeFlavor);
			List<CodeUnitInfo> infos = CollectionUtils.asList(list, CodeUnitInfo.class);
			Command cmd = new CodeUnitInfoPasteCmd(currentLocation.getAddress(), infos, pasteLabels,
				pasteComments);
			return tool.execute(cmd, currentProgram);
		}
		catch (Exception e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			tool.setStatusInfo("Paste failed: " + msg, true);
		}

		return false;
	}

	private boolean pasteLabelString(Transferable pasteData)
			throws UnsupportedFlavorException, IOException {

		String labelName =
			(String) pasteData.getTransferData(LabelStringTransferable.labelStringFlavor);
		Address address = currentLocation.getAddress();
		if (currentLocation instanceof LabelFieldLocation) {
			LabelFieldLocation labelFieldLocation = (LabelFieldLocation) currentLocation;
			String oldName = labelFieldLocation.getName();
			RenameLabelCmd cmd =
				new RenameLabelCmd(address, oldName, labelName, SourceType.USER_DEFINED);
			return tool.execute(cmd, currentProgram);
		}
		else if (currentLocation instanceof FunctionNameFieldLocation) {
			FunctionNameFieldLocation functionNameLocation =
				(FunctionNameFieldLocation) currentLocation;
			String oldName = functionNameLocation.getFunctionName();
			RenameLabelCmd cmd =
				new RenameLabelCmd(address, oldName, labelName, SourceType.USER_DEFINED);
			return tool.execute(cmd, currentProgram);
		}
		else if (currentLocation instanceof OperandFieldLocation) {
			return pasteOperandField((OperandFieldLocation) currentLocation, labelName);
		}

		// try pasting onto something that is not a label
		return maybePasteNonLabelString(labelName);
	}

	private boolean pasteOperandField(OperandFieldLocation operandLocation, String labelName) {

		int opIndex = operandLocation.getOperandIndex();
		Listing listing = currentProgram.getListing();
		Instruction instruction = listing.getInstructionAt(operandLocation.getAddress());
		if (instruction == null) {
			return false;
		}

		Reference reference = instruction.getPrimaryReference(opIndex);
		if (reference == null) {
			return false;
		}

		Variable var = currentProgram.getReferenceManager().getReferencedVariable(reference);
		if (var != null) {
			SetVariableNameCmd cmd =
				new SetVariableNameCmd(var, labelName, SourceType.USER_DEFINED);
			return tool.execute(cmd, currentProgram);
		}

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Symbol symbol = symbolTable.getSymbol(reference);
		if ((symbol instanceof CodeSymbol) || (symbol instanceof FunctionSymbol)) {
			String oldName = symbol.getName();
			Namespace namespace = symbol.getParentNamespace();
			Address symbolAddress = symbol.getAddress();
			RenameLabelCmd cmd = new RenameLabelCmd(symbolAddress, oldName, labelName, namespace,
				SourceType.USER_DEFINED);
			return tool.execute(cmd, currentProgram);
		}

		// try pasting onto something that is not a label
		return maybePasteNonLabelString(labelName);
	}

	private boolean pasteNonLabelString(Transferable pasteData)
			throws UnsupportedFlavorException, IOException {

		String text =
			(String) pasteData.getTransferData(NonLabelStringTransferable.nonLabelStringFlavor);
		return maybePasteNonLabelString(text);
	}

	private boolean maybePasteNonLabelString(String string) {
		if (currentLocation instanceof CommentFieldLocation) {
			CommentFieldLocation commentFieldLocation = (CommentFieldLocation) currentLocation;
			Address address = commentFieldLocation.getAddress();
			int commentType = commentFieldLocation.getCommentType();
			SetCommentCmd cmd = new SetCommentCmd(address, commentType, string);
			return tool.execute(cmd, currentProgram);
		}
		return false;
	}

	private void getCodeUnitInfo(AddressSetView set, Address startAddr, List<CodeUnitInfo> list,
			boolean copyLabels, boolean copyComments) {
		Map<Address, CodeUnitInfo> map = new HashMap<>();
		if (copyLabels) {
			getFunctions(startAddr, set, list, map);
			getLabels(startAddr, set, list, map);
		}
		if (copyComments) {
			getComments(startAddr, set, list, map);
		}
	}

	private void getFunctions(Address startAddr, AddressSetView set, List<CodeUnitInfo> list,
			Map<Address, CodeUnitInfo> map) {

		FunctionIterator iter = currentProgram.getListing().getFunctions(set, true);
		while (iter.hasNext()) {
			Function function = iter.next();
			Address entry = function.getEntryPoint();
			CodeUnitInfo info = getInfoFromMap(list, map, entry, startAddr);
			info.setFunction(function);
		}
	}

	private void getComments(Address startAddr, AddressSetView set, List<CodeUnitInfo> list,
			Map<Address, CodeUnitInfo> map) {

		CodeUnitIterator iter =
			currentProgram.getListing().getCodeUnitIterator(CodeUnit.COMMENT_PROPERTY, set, true);

		while (iter.hasNext()) {
			CodeUnit cu = iter.next();
			Address minAddress = cu.getMinAddress();
			CodeUnitInfo info = getInfoFromMap(list, map, minAddress, startAddr);
			setCommentInfo(cu, info);
		}
	}

	private void setCommentInfo(CodeUnit cu, CodeUnitInfo info) {

		for (int element : COMMENT_TYPES) {
			String[] comments = cu.getCommentAsArray(element);
			if (comments != null && comments.length > 0) {
				info.setComment(element, comments);
			}
		}
	}

	private void getLabels(Address startAddr, AddressSetView set, List<CodeUnitInfo> list,
			Map<Address, CodeUnitInfo> map) {

		SymbolIterator iter = currentProgram.getSymbolTable().getPrimarySymbolIterator(set, true);

		while (iter.hasNext()) {
			Symbol symbol = iter.next();
			Address minAddress = symbol.getAddress();
			Symbol[] symbols = currentProgram.getSymbolTable().getSymbols(minAddress);
			CodeUnitInfo info = getInfoFromMap(list, map, minAddress, startAddr);
			info.setSymbols(symbols);
		}
	}

	private CodeUnitInfo getInfoFromMap(List<CodeUnitInfo> list, Map<Address, CodeUnitInfo> map,
			Address minAddress, Address startAddr) {
		CodeUnitInfo info = map.get(minAddress);
		if (info == null) {
			long index = minAddress.subtract(startAddr);

			info = new CodeUnitInfo((int) index);
			map.put(minAddress, info);
			list.add(info);
		}

		return info;
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}
		return context.getComponentProvider() == componentProvider;
	}

	@Override
	public ComponentProvider getComponentProvider() {
		return componentProvider;
	}

	@Override
	public boolean enableCopy() {
		return true;
	}

	@Override
	public boolean enableCopySpecial() {
		return true;
	}

	@Override
	public boolean canCopy() {
		return copyFromSelectionEnabled || stringContent != null ||
			canCopyCurrentLocationWithNoSelection();
	}

	@Override
	public boolean canCopySpecial() {
		return currentLocation != null;
	}

	private boolean canCopyCurrentLocationWithNoSelection() {

		if (currentLocation instanceof AddressFieldLocation) {
			return true;
		}
		else if (currentLocation instanceof LabelFieldLocation) {
			return true;
		}
		else if (currentLocation instanceof FunctionNameFieldLocation) {
			return true;
		}
		else if (currentLocation instanceof CommentFieldLocation) {
			return true;
		}
		else if (currentLocation instanceof BytesFieldLocation) {
			return true;
		}
		else if (currentLocation instanceof OperandFieldLocation) {
			return true;
		}
		else if (currentLocation instanceof MnemonicFieldLocation) {
			return true;
		}
		else if (currentLocation instanceof VariableLocation) {
			return true;
		}

		return false;
	}

	@Override
	public boolean enablePaste() {
		return true;
	}

	@Override
	public boolean canPaste(DataFlavor[] availableFlavors) {
		if (availableFlavors != null) {
			for (DataFlavor flavor : availableFlavors) {
				if (flavor.equals(LABELS_COMMENTS_TYPE.getFlavor()) ||
					flavor.equals(LABELS_TYPE.getFlavor()) ||
					flavor.equals(COMMENTS_TYPE.getFlavor()) ||
					flavor.equals(BYTE_STRING_TYPE.getFlavor()) ||
					flavor.equals(LabelStringTransferable.labelStringFlavor) ||
					flavor.equals(NonLabelStringTransferable.nonLabelStringFlavor)) {
					return true;
				}
				if (flavor.equals(DataFlavor.stringFlavor)) {
					return true; // check if it is a valid hex string?
				}
			}
		}
		return false;
	}

//==================================================================================================
// Unsupported Operations
//==================================================================================================

	@Override
	public void lostOwnership(Transferable transferable) {
		// unsupported
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class LabelStringTransferable implements Transferable {

		public static final DataFlavor labelStringFlavor = new GenericDataFlavor(
			DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String",
			"Local label as string object");

		private final DataFlavor[] flavors = { labelStringFlavor, DataFlavor.stringFlavor };
		private final List<DataFlavor> flavorList = Arrays.asList(flavors);

		private String symbolName;

		LabelStringTransferable(String name) {
			this.symbolName = name;
		}

		@Override
		public Object getTransferData(DataFlavor flavor)
				throws UnsupportedFlavorException, IOException {
			if (flavor.equals(labelStringFlavor)) {
				return symbolName;
			}
			if (flavor.equals(DataFlavor.stringFlavor)) {
				return symbolName;
			}
			throw new UnsupportedFlavorException(flavor);
		}

		@Override
		public DataFlavor[] getTransferDataFlavors() {
			return flavors;
		}

		@Override
		public boolean isDataFlavorSupported(DataFlavor flavor) {
			return flavorList.contains(flavor);
		}
	}

	private static class NonLabelStringTransferable implements Transferable {

		public static final DataFlavor nonLabelStringFlavor = new GenericDataFlavor(
			DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String",
			"Local non-label as string object");

		private final DataFlavor[] flavors = { nonLabelStringFlavor, DataFlavor.stringFlavor };
		private final List<DataFlavor> flavorList = Arrays.asList(flavors);

		private String text;

		NonLabelStringTransferable(String[] text) {
			StringBuilder buildy = new StringBuilder();
			for (String string : text) {
				if (buildy.length() > 0) {
					buildy.append('\n');
				}
				buildy.append(string);
			}
			this.text = buildy.toString();
		}

		NonLabelStringTransferable(String text) {
			this.text = text;
		}

		@Override
		public Object getTransferData(DataFlavor flavor)
				throws UnsupportedFlavorException, IOException {
			if (flavor.equals(nonLabelStringFlavor)) {
				return text;
			}
			if (flavor.equals(DataFlavor.stringFlavor)) {
				return text;
			}
			throw new UnsupportedFlavorException(flavor);
		}

		@Override
		public DataFlavor[] getTransferDataFlavors() {
			return flavors;
		}

		@Override
		public boolean isDataFlavorSupported(DataFlavor flavor) {
			return flavorList.contains(flavor);
		}
	}
}
