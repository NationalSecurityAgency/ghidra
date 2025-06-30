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
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.watch.WatchRow;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.options.SaveState;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
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

public class DefaultWatchRow implements WatchRow {
	public static final int TRUNCATE_BYTES_LENGTH = 64;
	private static final String KEY_EXPRESSION = "expression";
	private static final String KEY_DATA_TYPE = "dataType";
	private static final String KEY_SETTINGS = "settings";

	private final DebuggerWatchesProvider provider;

	private final Object lock = new Object();

	private String expression;
	private String typePath;
	private DataType dataType;
	private SettingsImpl settings = new SettingsImpl();
	private SavedSettings savedSettings = new SavedSettings(settings);

	private volatile PcodeExpression compiled;
	private volatile TraceMemoryState state;
	private volatile Address address;
	private volatile Symbol symbol;
	private volatile AddressSetView reads;
	private volatile byte[] value;
	private volatile byte[] prevValue; // Value at previous coordinates
	private volatile String valueString;
	private volatile Object valueObj;
	private volatile Throwable error = null;

	public DefaultWatchRow(DebuggerWatchesProvider provider, String expression) {
		this.provider = provider;
		this.expression = expression;
	}

	protected void blank() {
		synchronized (lock) {
			state = null;
			address = null;
			symbol = null;
			reads = null;
			value = null;
			valueString = null;
			valueObj = null;
		}
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
		PcodeExecutor<WatchValue> executor;
		PcodeExecutor<byte[]> prevExec;
		final String expression;
		synchronized (lock) {
			blank();
			executor = provider.asyncWatchExecutor;
			prevExec = provider.prevValueExecutor;
			if (executor == null) {
				provider.contextChanged();
				return;
			}
			expression = this.expression;
		}
		CompletableFuture.runAsync(() -> {
			synchronized (lock) {
				recompile();
				if (compiled == null) {
					return;
				}
			}
			// Do not accidentally hang the Swing thread on evaluation
			WatchValue fullValue = compiled.evaluate(executor);
			byte[] prevValue;
			try {
				prevValue = prevExec == null ? null : compiled.evaluate(prevExec);
			}
			catch (Exception e) {
				Msg.trace(this, "Error in evaluating previous value. Ignoring.", e);
				prevValue = null;
			}
			synchronized (lock) {
				if (executor != provider.asyncWatchExecutor) {
					return;
				}
				if (!Objects.equals(expression, this.expression)) {
					return;
				}
				TracePlatform platform = provider.current.getPlatform();
				this.prevValue = prevValue;
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
			}
		}, provider.workQueue).exceptionally(e -> {
			error = e;
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

	@Override
	public void setExpression(String expression) {
		synchronized (lock) {
			if (!Objects.equals(this.expression, expression)) {
				prevValue = null;
				// NB. Allow fall-through so user can re-evaluate via nop edit.
			}
			this.expression = expression;
			this.compiled = null;
			reevaluate();
		}
	}

	@Override
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

	@Override
	public void setDataType(DataType dataType) {
		synchronized (lock) {
			if (dataType instanceof Pointer ptrType && address != null &&
				address.isRegisterAddress()) {
				/**
				 * NOTE: This will not catch it if the expression cannot be evaluated. When it can
				 * later be evaluated, no check is performed.
				 * 
				 * TODO: This should be for the current platform. These don't depend on the trace's
				 * code storage, so it should be easier to implement. Still, I'll wait to tackle
				 * that all at once.
				 */
				AddressSpace space =
					provider.current.getTrace().getBaseAddressFactory().getDefaultAddressSpace();
				DataTypeManager dtm = ptrType.getDataTypeManager();
				dataType =
					new PointerTypedef(null, ptrType.getDataType(), ptrType.getLength(), dtm,
						space);
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
				savedSettings.read(dataType.getSettingsDefinitions(),
					dataType.getDefaultSettings());
			}
		}
	}

	@Override
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
	@Override
	public Settings getSettings() {
		return settings;
	}

	@Override
	public void settingsChanged() {
		synchronized (lock) {
			if (dataType != null) {
				savedSettings.write(dataType.getSettingsDefinitions(),
					dataType.getDefaultSettings());
			}
			valueString = parseAsDataTypeStr();
		}
		provider.watchTableModel.fireTableDataChanged();
	}

	@Override
	public Address getAddress() {
		synchronized (lock) {
			return address;
		}
	}

	@Override
	public AddressRange getRange() {
		synchronized (lock) {
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
	}

	@Override
	public String getRawValueString() {
		synchronized (lock) {
			byte[] value = this.value;
			Language language = provider.language;
			if (value == null || language == null) {
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
	}

	/**
	 * Get the memory read by the watch, from the host platform perspective
	 * 
	 * @return the reads
	 */
	@Override
	public AddressSetView getReads() {
		synchronized (lock) {
			return reads;
		}
	}

	public TraceMemoryState getState() {
		synchronized (lock) {
			return state;
		}
	}

	@Override
	public byte[] getValue() {
		synchronized (lock) {
			return value;
		}
	}

	@Override
	public String getValueString() {
		synchronized (lock) {
			return valueString;
		}
	}

	@Override
	public Object getValueObject() {
		synchronized (lock) {
			return valueObj;
		}
	}

	@Override
	public boolean isRawValueEditable() {
		synchronized (lock) {
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
	}

	@Override
	public void setRawValueString(String valueString) {
		if (!isRawValueEditable()) {
			throw new IllegalStateException("Watch is not editable");
		}
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
		synchronized (lock) {
			if (address == null) {
				throw new IllegalStateException(
					"Cannot write to watch variable without an address");
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
	}

	@Override
	public void setValueString(String valueString) {
		synchronized (lock) {
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
	}

	@Override
	public boolean isValueEditable() {
		synchronized (lock) {
			if (!isRawValueEditable()) {
				return false;
			}
			if (dataType == null) {
				return false;
			}
			return dataType.isEncodable();
		}
	}

	@Override
	public int getValueLength() {
		synchronized (lock) {
			return value == null ? 0 : value.length;
		}
	}

	protected Symbol computeSymbol() {
		if (address == null || !address.isMemoryAddress()) {
			return null;
		}
		DebuggerCoordinates current = provider.current;
		Trace trace = current.getTrace();
		Collection<? extends TraceLabelSymbol> labels =
			trace.getSymbolManager().labels().getAt(current.getSnap(), address, false);
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

	@Override
	public Symbol getSymbol() {
		synchronized (lock) {
			return symbol;
		}
	}

	@Override
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

	@Override
	public Throwable getError() {
		return error;
	}

	@Override
	public boolean isKnown() {
		synchronized (lock) {
			return state == TraceMemoryState.KNOWN;
		}
	}

	@Override
	public boolean isChanged() {
		synchronized (lock) {
			if (prevValue == null) {
				return false;
			}
			return !Arrays.equals(value, prevValue);
		}
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
