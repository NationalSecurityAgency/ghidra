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

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.docking.settings.SettingsImpl;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.trace.TraceBytesPcodeExecutorState;
import ghidra.pcode.exec.trace.TraceSleighUtils;
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
	private SleighLanguage language;
	private PcodeExecutor<Pair<byte[], TraceMemoryState>> executorWithState;
	private ReadDepsPcodeExecutor executorWithAddress;
	private AsyncPcodeExecutor<byte[]> asyncExecutor;

	private String expression;
	private DataType dataType;

	private SleighExpression compiled;
	private TraceMemoryState state;
	private Address address;
	private AddressSet reads;
	private byte[] value;
	private String valueString;
	private String error = "";

	public WatchRow(DebuggerWatchesProvider provider, String expression) {
		this.provider = provider;
		this.expression = expression;
	}

	protected void blank() {
		error = null;
		compiled = null;
		state = null;
		address = null;
		reads = null;
		value = null;
		valueString = null;
	}

	protected void recompile() {
		this.error = null;
		try {
			this.compiled = SleighProgramCompiler.compileExpression(language, expression);
		}
		catch (Exception e) {
			this.error = e.getMessage();
			return;
		}
	}

	protected void doTargetReads() {
		if (asyncExecutor != null) {
			compiled.evaluate(asyncExecutor).exceptionally(ex -> {
				error = ex.getMessage();
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
		try {
			Pair<byte[], TraceMemoryState> valueWithState = compiled.evaluate(executorWithState);
			Pair<byte[], Address> valueWithAddress = compiled.evaluate(executorWithAddress);

			value = valueWithState.getLeft();
			state = valueWithState.getRight();
			address = valueWithAddress.getRight();
			reads = executorWithAddress.getReads();

			valueString = parseAsDataType();
		}
		catch (Exception e) {
			error = e.getMessage();
		}
	}

	protected String parseAsDataType() {
		if (dataType == null) {
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
		protected byte[] getFromSpace(TraceMemorySpace space, long offset, int size) {
			byte[] data = super.getFromSpace(space, offset, size);
			try {
				reads.add(
					new AddressRangeImpl(space.getAddressSpace().getAddress(offset), data.length));
			}
			catch (AddressOverflowException | AddressOutOfBoundsException e) {
				throw new AssertionError(e);
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
		public void execute(SleighProgram program,
				SleighUseropLibrary<Pair<byte[], Address>> library) {
			depsState.reset();
			super.execute(program, library);
		}

		public AddressSet getReads() {
			return depsState.getReads();
		}
	}

	protected static ReadDepsPcodeExecutor buildAddressDepsExecutor(
			DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		ReadDepsTraceBytesPcodeExecutorState state =
			new ReadDepsTraceBytesPcodeExecutorState(trace, coordinates.getSnap(),
				coordinates.getThread(), coordinates.getFrame());
		Language language = trace.getBaseLanguage();
		PcodeExecutorState<Pair<byte[], Address>> paired =
			state.paired(new AddressOfPcodeExecutorState(language.isBigEndian()));
		PairedPcodeArithmetic<byte[], Address> arithmetic = new PairedPcodeArithmetic<>(
			BytesPcodeArithmetic.forLanguage(language), AddressOfPcodeArithmetic.INSTANCE);
		return new ReadDepsPcodeExecutor(state, language, arithmetic, paired);
	}

	public void setContext(DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		if (trace == null) {
			blank();
			error = "No trace nor thread active";
			return;
		}
		Language newLanguage = trace.getBaseLanguage();
		if (this.language != newLanguage) {
			if (!(newLanguage instanceof SleighLanguage)) {
				error = "No a sleigh-based langauge";
				return;
			}
			this.language = (SleighLanguage) newLanguage;
			recompile();
		}
		boolean live = coordinates.isAlive() && coordinates.isPresent();
		if (live) {
			this.asyncExecutor = TracePcodeUtils.executorForCoordinates(coordinates);
		}
		this.executorWithState = TraceSleighUtils.buildByteWithStateExecutor(trace,
			coordinates.getSnap(), coordinates.getThread(), coordinates.getFrame());
		this.executorWithAddress = buildAddressDepsExecutor(coordinates);
		if (live) {
			doTargetReads();
		}
		reevaluate(); // NB. Target reads may not cause database changes
	}

	public void setExpression(String expression) {
		this.expression = expression;
		recompile();
	}

	public String getExpression() {
		return expression;
	}

	public void setDataType(DataType dataType) {
		this.dataType = dataType;
	}

	public DataType getDataType() {
		return dataType;
	}

	public Address getAddress() {
		return address;
	}

	public String getRawValueString() {
		if (value.length > 20) {
			return NumericUtilities.convertBytesToString(value, 0, 20, " ") + "...";
		}
		return NumericUtilities.convertBytesToString(value, " ");
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

	public String getError() {
		return error;
	}
}
