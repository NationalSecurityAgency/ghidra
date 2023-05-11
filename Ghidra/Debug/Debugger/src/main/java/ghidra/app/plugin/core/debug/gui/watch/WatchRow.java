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
package ghidra.app.plugin.core.debug.gui.watch;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import db.Transaction;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.async.AsyncUtils;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.options.SaveState;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.symbol.TraceLabelSymbol;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

public class WatchRow {
	public static final int TRUNCATE_BYTES_LENGTH = 64;
	private static final String KEY_EXPRESSION = "expression";
	private static final String KEY_DATA_TYPE = "dataType";
	private static final String KEY_SETTINGS = "settings";

	private final DebuggerWatchesProvider provider;

	private String expression;
	private String typePath;
	private DataType dataType;
	private SettingsImpl settings = new SettingsImpl();
	private SavedSettings savedSettings = new SavedSettings(settings);

	private PcodeExpression compiled;
	private TraceMemoryState state;
	private Address address;
	private Symbol symbol;
	private AddressSetView reads;
	private byte[] value;
	private byte[] prevValue; // Value at previous coordinates
	private String valueString;
	private Object valueObj;
	private Throwable error = null;

	public WatchRow(DebuggerWatchesProvider provider, String expression) {
		this.provider = provider;
		this.expression = expression;
	}

	protected void blank() {
		state = null;
		address = null;
		symbol = null;
		reads = null;
		value = null;
		valueString = null;
		valueObj = null;
	}

	protected void recompile() {
		compiled = null;
		error = null;
		if (provider.language == null) {
			return;
		}
		if (expression == null || expression.length() == 0) {
			return;
		}
		try {
			compiled = DebuggerPcodeUtils.compileExpression(provider.getTool(), provider.current,
				expression);
		}
		catch (Exception e) {
			error = e;
			return;
		}
	}

	protected void reevaluate() {
		blank();
		PcodeExecutor<WatchValue> executor = provider.asyncWatchExecutor;
		PcodeExecutor<byte[]> prevExec = provider.prevValueExecutor;
		if (executor == null) {
			provider.contextChanged();
			return;
		}
		CompletableFuture.runAsync(() -> {
			recompile();
			if (compiled == null) {
				provider.contextChanged();
				return;
			}

			WatchValue fullValue = compiled.evaluate(executor);
			prevValue = prevExec == null ? null : compiled.evaluate(prevExec);

			TracePlatform platform = provider.current.getPlatform();
			value = fullValue.bytes().bytes();
			error = null;
			state = fullValue.state();
			// TODO: Optional column for guest address?
			address = platform.mapGuestToHost(fullValue.address());
			symbol = computeSymbol();
			// reads piece uses trace access to translate to host/overlay already
			reads = fullValue.reads();

			valueObj = parseAsDataTypeObj();
			valueString = parseAsDataTypeStr();
		}, provider.workQueue).exceptionally(e -> {
			error = e;
			provider.contextChanged();
			return null;
		}).thenRunAsync(() -> {
			provider.watchTableModel.fireTableDataChanged();
			provider.contextChanged();
		}, AsyncUtils.SWING_EXECUTOR);
	}

	private ByteMemBufferImpl createMemBuffer() {
		return new ByteMemBufferImpl(address, value, provider.language.isBigEndian()) {
			@Override
			public Memory getMemory() {
				return provider.current.getTrace().getProgramView().getMemory();
			}
		};
	}

	protected String parseAsDataTypeStr() {
		if (dataType == null || value == null) {
			return "";
		}
		MemBuffer buffer = createMemBuffer();
		return dataType.getRepresentation(buffer, settings, value.length);
	}

	protected Object parseAsDataTypeObj() {
		if (dataType == null || value == null) {
			return null;
		}
		MemBuffer buffer = createMemBuffer();
		return dataType.getValue(buffer, settings, value.length);
	}

	public void setExpression(String expression) {
		if (!Objects.equals(this.expression, expression)) {
			prevValue = null;
			// NB. Allow fall-through so user can re-evaluate via nop edit.
		}
		this.expression = expression;
		this.compiled = null;
		reevaluate();
	}

	public String getExpression() {
		return expression;
	}

	protected void updateType() {
		dataType = null;
		if (typePath == null) {
			return;
		}
		// Try from the trace first
		Trace trace = provider.current.getTrace();
		if (trace != null) {
			dataType = trace.getDataTypeManager().getDataType(typePath);
			if (dataType != null) {
				return;
			}
		}
		// Either we have no trace, or the trace doesn't have the type.
		// Try built-ins
		DataTypeManagerService dtms = provider.getTool().getService(DataTypeManagerService.class);
		if (dtms != null) {
			dataType = dtms.getBuiltInDataTypesManager().getDataType(typePath);
		}
		// We're out of things to try, let null be null
	}

	public void setTypePath(String typePath) {
		this.typePath = typePath;
		updateType();
	}

	public String getTypePath() {
		return typePath;
	}

	public void setDataType(DataType dataType) {
		if (dataType instanceof Pointer ptrType && address != null &&
			address.isRegisterAddress()) {
			/**
			 * NOTE: This will not catch it if the expression cannot be evaluated. When it can later
			 * be evaluated, no check is performed.
			 * 
			 * TODO: This should be for the current platform. These don't depend on the trace's code
			 * storage, so it should be easier to implement. Still, I'll wait to tackle that all at
			 * once.
			 */
			AddressSpace space =
				provider.current.getTrace().getBaseAddressFactory().getDefaultAddressSpace();
			DataTypeManager dtm = ptrType.getDataTypeManager();
			dataType =
				new PointerTypedef(null, ptrType.getDataType(), ptrType.getLength(), dtm, space);
			if (dtm != null) {
				try (Transaction tid = dtm.openTransaction("Resolve data type")) {
					dataType = dtm.resolve(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
			}
		}
		this.typePath = dataType == null ? null : dataType.getPathName();
		this.dataType = dataType;
		settings.setDefaultSettings(dataType == null ? null : dataType.getDefaultSettings());
		valueString = parseAsDataTypeStr();
		valueObj = parseAsDataTypeObj();
		provider.contextChanged();
		if (dataType != null) {
			savedSettings.read(dataType.getSettingsDefinitions(), dataType.getDefaultSettings());
		}
	}

	public DataType getDataType() {
		return dataType;
	}

	/**
	 * Get the row's (mutable) data type settings
	 * 
	 * <p>
	 * After mutating these settings, the client must call {@link #settingsChanged()} to update the
	 * row's display and save state.
	 * 
	 * @return the settings
	 */
	public Settings getSettings() {
		return settings;
	}

	protected void settingsChanged() {
		if (dataType != null) {
			savedSettings.write(dataType.getSettingsDefinitions(), dataType.getDefaultSettings());
		}
		valueString = parseAsDataTypeStr();
		provider.watchTableModel.fireTableDataChanged();
	}

	public Address getAddress() {
		return address;
	}

	public AddressRange getRange() {
		if (address == null || value == null) {
			return null;
		}
		if (address.isConstantAddress()) {
			return new AddressRangeImpl(address, address);
		}
		try {
			return new AddressRangeImpl(address, value.length);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	public String getRawValueString() {
		if (value == null || provider.language == null) {
			return "??";
		}
		if (address == null || !address.getAddressSpace().isMemorySpace()) {
			BigInteger asBigInt = Utils.bytesToBigInteger(value, value.length,
				provider.language.isBigEndian(), false);
			return "0x" + asBigInt.toString(16);
		}
		if (value.length > TRUNCATE_BYTES_LENGTH) {
			// TODO: I'd like this not to affect the actual value, just the display
			//   esp., since this will be the "value" when starting to edit.
			return "{ " +
				NumericUtilities.convertBytesToString(value, 0, TRUNCATE_BYTES_LENGTH, " ") +
				" ... }";
		}
		return "{ " + NumericUtilities.convertBytesToString(value, " ") + " }";
	}

	/**
	 * Get the memory read by the watch, from the host platform perspective
	 * 
	 * @return the reads
	 */
	public AddressSetView getReads() {
		return reads;
	}

	public TraceMemoryState getState() {
		return state;
	}

	public byte[] getValue() {
		return value;
	}

	public String getValueString() {
		return valueString;
	}

	public Object getValueObj() {
		return valueObj;
	}

	public boolean isRawValueEditable() {
		if (!provider.isEditsEnabled()) {
			return false;
		}
		if (address == null) {
			return false;
		}
		DebuggerControlService controlService = provider.controlService;
		if (controlService == null) {
			return false;
		}
		StateEditor editor = controlService.createStateEditor(provider.current);
		return editor.isVariableEditable(address, getValueLength());
	}

	public void setRawValueString(String valueString) {
		valueString = valueString.trim();
		if (valueString.startsWith("{")) {
			if (!valueString.endsWith("}")) {
				throw new NumberFormatException("Byte array values must be hex enclosed in {}");
			}

			setRawValueBytesString(valueString.substring(1, valueString.length() - 1));
			return;
		}

		setRawValueIntString(valueString);
	}

	public void setRawValueBytesString(String bytesString) {
		setRawValueBytes(NumericUtilities.convertStringToBytes(bytesString));
	}

	public void setRawValueIntString(String intString) {
		intString = intString.trim();
		final BigInteger val;
		if (intString.startsWith("0x")) {
			val = new BigInteger(intString.substring(2), 16);
		}
		else {
			val = new BigInteger(intString, 10);
		}
		setRawValueBytes(
			Utils.bigIntegerToBytes(val, value.length, provider.language.isBigEndian()));
	}

	public void setRawValueBytes(byte[] bytes) {
		if (address == null) {
			throw new IllegalStateException("Cannot write to watch variable without an address");
		}
		if (bytes.length > value.length) {
			throw new IllegalArgumentException("Byte arrays cannot exceed length of variable");
		}
		if (bytes.length < value.length) {
			byte[] fillOld = Arrays.copyOf(value, value.length);
			System.arraycopy(bytes, 0, fillOld, 0, bytes.length);
			bytes = fillOld;
		}
		DebuggerControlService controlService = provider.controlService;
		if (controlService == null) {
			throw new AssertionError("No control service");
		}
		StateEditor editor = controlService.createStateEditor(provider.current);
		editor.setVariable(address, bytes).exceptionally(ex -> {
			Msg.showError(this, null, "Write Failed",
				"Could not modify watch value (on target)", ex);
			return null;
		});
	}

	public void setValueString(String valueString) {
		if (dataType == null || value == null) {
			// isValueEditable should have been false
			provider.getTool().setStatusInfo("Watch no value or no data type", true);
			return;
		}
		try {
			byte[] encoded = dataType.encodeRepresentation(valueString,
				new ByteMemBufferImpl(address, value, provider.language.isBigEndian()),
				SettingsImpl.NO_SETTINGS, value.length);
			setRawValueBytes(encoded);
		}
		catch (DataTypeEncodeException e) {
			provider.getTool().setStatusInfo(e.getMessage(), true);
		}
	}

	public boolean isValueEditable() {
		if (!isRawValueEditable()) {
			return false;
		}
		if (dataType == null) {
			return false;
		}
		return dataType.isEncodable();
	}

	public int getValueLength() {
		return value == null ? 0 : value.length;
	}

	protected Symbol computeSymbol() {
		if (address == null || !address.isMemoryAddress()) {
			return null;
		}
		DebuggerCoordinates current = provider.current;
		Trace trace = current.getTrace();
		Collection<? extends TraceLabelSymbol> labels =
			trace.getSymbolManager().labels().getAt(current.getSnap(), null, address, false);
		if (!labels.isEmpty()) {
			return labels.iterator().next();
		}
		// TODO: Check trace functions? They don't work yet.
		if (provider.mappingService == null) {
			return null;
		}
		TraceLocation dloc =
			new DefaultTraceLocation(trace, null, Lifespan.at(current.getSnap()), address);
		ProgramLocation sloc = provider.mappingService.getOpenMappedLocation(dloc);
		if (sloc == null) {
			return null;
		}

		Program program = sloc.getProgram();
		SymbolTable table = program.getSymbolTable();
		Symbol primary = table.getPrimarySymbol(address);
		if (primary != null) {
			return primary;
		}
		SymbolIterator sit = table.getSymbolsAsIterator(sloc.getByteAddress());
		if (sit.hasNext()) {
			return sit.next();
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function != null) {
			return function.getSymbol();
		}
		return null;
	}

	public Symbol getSymbol() {
		return symbol;
	}

	public String getErrorMessage() {
		if (error == null) {
			return "";
		}
		String message = error.getMessage();
		if (message != null && message.trim().length() != 0) {
			return message;
		}
		return error.getClass().getSimpleName();
	}

	public Throwable getError() {
		return error;
	}

	public boolean isKnown() {
		return state == TraceMemoryState.KNOWN;
	}

	public boolean isChanged() {
		if (prevValue == null) {
			return false;
		}
		return !Arrays.equals(value, prevValue);
	}

	protected void writeConfigState(SaveState saveState) {
		saveState.putString(KEY_EXPRESSION, expression);
		saveState.putString(KEY_DATA_TYPE, typePath);
		saveState.putSaveState(KEY_SETTINGS, savedSettings.getState());
	}

	protected void readConfigState(SaveState saveState) {
		setExpression(saveState.getString(KEY_EXPRESSION, ""));
		setTypePath(saveState.getString(KEY_DATA_TYPE, null));

		savedSettings.setState(saveState.getSaveState(KEY_SETTINGS));
		if (dataType != null) {
			savedSettings.read(dataType.getSettingsDefinitions(), dataType.getDefaultSettings());
		}
	}
}
