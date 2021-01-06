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
import java.util.Arrays;
import java.util.Objects;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.DataTypeManagerService;
import ghidra.docking.settings.SettingsImpl;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.trace.TraceBytesPcodeExecutorState;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.NumericUtilities;
import ghidra.util.Swing;

public class WatchRow {
	private final DebuggerWatchesProvider provider;
	private Trace trace;
	private SleighLanguage language;
	private PcodeExecutor<Pair<byte[], TraceMemoryState>> executorWithState;
	private ReadDepsPcodeExecutor executorWithAddress;
	private AsyncPcodeExecutor<byte[]> asyncExecutor;

	private String expression;
	private String typePath;
	private DataType dataType;

	private SleighExpression compiled;
	private TraceMemoryState state;
	private Address address;
	private AddressSet reads;
	private byte[] value;
	private byte[] prevValue; // Value at previous coordinates
	private String valueString;
	private Throwable error = null;

	public WatchRow(DebuggerWatchesProvider provider, String expression) {
		this.provider = provider;
		this.expression = expression;
	}

	protected void blank() {
		state = null;
		address = null;
		reads = null;
		value = null;
		valueString = null;
	}

	protected void recompile() {
		compiled = null;
		error = null;
		if (expression == null || expression.length() == 0) {
			return;
		}
		if (language == null) {
			return;
		}
		try {
			compiled = SleighProgramCompiler.compileExpression(language, expression);
		}
		catch (Exception e) {
			error = e;
			return;
		}
	}

	protected void doTargetReads() {
		if (compiled != null && asyncExecutor != null) {
			compiled.evaluate(asyncExecutor).exceptionally(ex -> {
				error = ex;
				Swing.runIfSwingOrRunLater(() -> {
					provider.watchTableModel.notifyUpdated(this);
				});
				return null;
			});
			// NB. Re-evaluation triggered by database changes, or called separately
		}
	}

	protected void reevaluate() {
		blank();
		if (trace == null || compiled == null) {
			return;
		}
		try {
			Pair<byte[], TraceMemoryState> valueWithState = compiled.evaluate(executorWithState);
			Pair<byte[], Address> valueWithAddress = compiled.evaluate(executorWithAddress);

			value = valueWithState.getLeft();
			error = null;
			state = valueWithState.getRight();
			address = valueWithAddress.getRight();
			reads = executorWithAddress.getReads();

			valueString = parseAsDataType();
		}
		catch (Exception e) {
			error = e;
		}
	}

	protected String parseAsDataType() {
		if (dataType == null || value == null) {
			return "";
		}
		MemBuffer buffer = new ByteMemBufferImpl(address, value, language.isBigEndian());
		return dataType.getRepresentation(buffer, SettingsImpl.NO_SETTINGS, value.length);
	}

	public static class ReadDepsTraceBytesPcodeExecutorState
			extends TraceBytesPcodeExecutorState {
		private AddressSet reads = new AddressSet();

		public ReadDepsTraceBytesPcodeExecutorState(Trace trace, long snap, TraceThread thread,
				int frame) {
			super(trace, snap, thread, frame);
		}

		@Override
		public byte[] getVar(AddressSpace space, long offset, int size,
				boolean truncateAddressableUnit) {
			byte[] data = super.getVar(space, offset, size, truncateAddressableUnit);
			if (space.isMemorySpace()) {
				offset = truncateOffset(space, offset);
			}
			if (space.isMemorySpace() || space.isRegisterSpace()) {
				try {
					reads.add(new AddressRangeImpl(space.getAddress(offset), data.length));
				}
				catch (AddressOverflowException | AddressOutOfBoundsException e) {
					throw new AssertionError(e);
				}
			}
			return data;
		}

		@Override
		protected void setInSpace(TraceMemorySpace space, long offset, int size, byte[] val) {
			throw new UnsupportedOperationException("Expression cannot write to trace");
		}

		public void reset() {
			reads = new AddressSet();
		}

		public AddressSet getReads() {
			return new AddressSet(reads);
		}
	}

	public static class ReadDepsPcodeExecutor
			extends PcodeExecutor<Pair<byte[], Address>> {
		private ReadDepsTraceBytesPcodeExecutorState depsState;

		public ReadDepsPcodeExecutor(ReadDepsTraceBytesPcodeExecutorState depsState,
				Language language, PairedPcodeArithmetic<byte[], Address> arithmetic,
				PcodeExecutorState<Pair<byte[], Address>> state) {
			super(language, arithmetic, state);
			this.depsState = depsState;
		}

		@Override
		public PcodeFrame execute(PcodeProgram program,
				SleighUseropLibrary<Pair<byte[], Address>> library) {
			depsState.reset();
			return super.execute(program, library);
		}

		public AddressSet getReads() {
			return depsState.getReads();
		}
	}

	protected static ReadDepsPcodeExecutor buildAddressDepsExecutor(
			DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		ReadDepsTraceBytesPcodeExecutorState state =
			new ReadDepsTraceBytesPcodeExecutorState(trace, coordinates.getViewSnap(),
				coordinates.getThread(), coordinates.getFrame());
		Language language = trace.getBaseLanguage();
		PcodeExecutorState<Pair<byte[], Address>> paired =
			state.paired(new AddressOfPcodeExecutorState(language.isBigEndian()));
		PairedPcodeArithmetic<byte[], Address> arithmetic = new PairedPcodeArithmetic<>(
			BytesPcodeArithmetic.forLanguage(language), AddressOfPcodeArithmetic.INSTANCE);
		return new ReadDepsPcodeExecutor(state, language, arithmetic, paired);
	}

	public void setCoordinates(DebuggerCoordinates coordinates) {
		// NB. Caller has already verified coordinates actually changed
		prevValue = value;
		trace = coordinates.getTrace();
		updateType();
		if (trace == null) {
			blank();
			return;
		}
		Language newLanguage = trace.getBaseLanguage();
		if (language != newLanguage) {
			if (!(newLanguage instanceof SleighLanguage)) {
				error = new RuntimeException("Not a sleigh-based langauge");
				return;
			}
			language = (SleighLanguage) newLanguage;
			recompile();
		}
		if (coordinates.isAliveAndReadsPresent()) {
			asyncExecutor = TracePcodeUtils.executorForCoordinates(coordinates);
		}
		executorWithState = TraceSleighUtils.buildByteWithStateExecutor(trace,
			coordinates.getViewSnap(), coordinates.getThread(), coordinates.getFrame());
		executorWithAddress = buildAddressDepsExecutor(coordinates);
	}

	public void setExpression(String expression) {
		if (!Objects.equals(this.expression, expression)) {
			prevValue = null;
			// NB. Allow fall-through so user can re-evaluate via nop edit.
		}
		this.expression = expression;
		blank();
		recompile();
		if (error != null) {
			provider.contextChanged();
			return;
		}
		if (asyncExecutor != null) {
			doTargetReads();
		}
		reevaluate();
		provider.contextChanged();
	}

	public String getExpression() {
		return expression;
	}

	protected void updateType() {
		dataType = null;
		if (trace == null || typePath == null) {
			return;
		}
		dataType = trace.getDataTypeManager().getDataType(typePath);
		if (dataType != null) {
			return;
		}
		DataTypeManagerService dtms = provider.getTool().getService(DataTypeManagerService.class);
		if (dtms == null) {
			return;
		}
		dataType = dtms.getBuiltInDataTypesManager().getDataType(typePath);
	}

	public void setTypePath(String typePath) {
		this.typePath = typePath;
		updateType();
	}

	public String getTypePath() {
		return typePath;
	}

	public void setDataType(DataType dataType) {
		this.typePath = dataType == null ? null : dataType.getPathName();
		this.dataType = dataType;
		valueString = parseAsDataType();
		provider.contextChanged();
	}

	public DataType getDataType() {
		return dataType;
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
		if (value == null) {
			return "??";
		}
		if (address == null || !address.getAddressSpace().isMemorySpace()) {
			BigInteger asBigInt =
				Utils.bytesToBigInteger(value, value.length, language.isBigEndian(), false);
			return "0x" + asBigInt.toString(16);
		}
		if (value.length > 20) {
			return "{ " + NumericUtilities.convertBytesToString(value, 0, 20, " ") + " ... }";
		}
		return "{ " + NumericUtilities.convertBytesToString(value, " ") + " }";
	}

	public AddressSet getReads() {
		return reads;
	}

	public TraceMemoryState getState() {
		return state;
	}

	public String getValueString() {
		return valueString;
	}

	public int getValueLength() {
		return value == null ? 0 : value.length;
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
}
