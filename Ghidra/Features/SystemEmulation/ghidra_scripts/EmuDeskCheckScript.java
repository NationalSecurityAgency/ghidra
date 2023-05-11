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
import java.util.*;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.core.debug.service.emulation.BytesDebuggerPcodeEmulator;
import ghidra.app.plugin.core.debug.service.emulation.data.DefaultPcodeDebuggerAccess;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.docking.settings.*;
import ghidra.pcode.emu.BytesPcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.struct.StructuredSleigh;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.symbol.Symbol;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * NOTE: Testing with bash: set_shellopts
 */
public class EmuDeskCheckScript extends GhidraScript implements FlatDebuggerAPI {

	public class Injects extends StructuredSleigh {
		Var RAX = lang("RAX", type("void *"));
		Var RSP = lang("RSP", type("void *"));

		protected Injects() {
			super(currentProgram);
		}

		public Var POP() {
			Var tgt = local("tgt", RSP.cast(type("void **")).deref());
			RSP.set(RSP.addi(8));
			return tgt;
		}

		public void RET() {
			_goto(POP());
		}

		public void RET(RVal val) {
			RAX.set(val);
			RET();
		}

		/**
		 * TODO: A framework for stubbing the functions. This is close, and the system calls stuff
		 * can get us closer in its handling of calling conventions. We need either to generate
		 * Sleigh that gets the parameters in place, or if we're going to use the aliasing idea that
		 * the syscall stuff does, then we need to allow injection of the already-compiled Sleigh
		 * program. For now, we'll have to declare the parameter-holding register as a language
		 * variable.
		 */
		@StructuredUserop
		public void strlen(/*@Param(name = "RDI", type = "char *") Var s*/) {
			Var s = lang("RDI", type("char *"));
			Var t = temp(type("char *"));
			_for(t.set(s), t.deref().neq(0), t.inc(), () -> {
			});
			RET(t.subi(s));
		}
	}

	public final List<Watch> watches = List.of(
		watch("RAX", type("int")),
		watch("RCX", type("int"),
			set(FormatSettingsDefinition.DEF, FormatSettingsDefinition.DECIMAL)),
		watch("RSP", type("void *")));
	// TODO: Snarf from Watches window?

	@Override
	protected void run() throws Exception {
		Trace trace = emulateLaunch(currentProgram, currentAddress);
		TracePlatform platform = trace.getPlatformManager().getHostPlatform();
		long snap = 0;

		TableChooserDialog tableDialog =
			createTableChooserDialog("Desk Check", new CheckRowChooser());

		tableDialog.show();

		tableDialog.addCustomColumn(new CheckRowScheduleDisplay());
		tableDialog.addCustomColumn(new CheckRowCounterDisplay());

		List<PcodeExpression> compiled = new ArrayList<>();
		TypeLoader loader = new TypeLoader(currentProgram);
		for (Watch w : watches) {
			PcodeExpression ce = SleighProgramCompiler
					.compileExpression((SleighLanguage) platform.getLanguage(), w.expression);
			tableDialog.addCustomColumn(new CheckRowWatchDisplay(loader, w, compiled.size()));
			compiled.add(ce);
		}

		TraceSchedule schedule;
		while (true) {
			try {
				schedule = TraceSchedule
						.parse(askString("Schedule", "Enter the steping schedule", "0:t0-1000"));
				break;
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				Msg.showError(this, null, "Schedule", "Error: " + e);
			}
		}

		BytesDebuggerPcodeEmulator emu = new BytesDebuggerPcodeEmulator(
			new DefaultPcodeDebuggerAccess(state.getTool(), null, platform, snap)) {
			TraceSchedule position = TraceSchedule.snap(snap);

			@Override
			protected BytesPcodeThread createThread(String name) {
				return new BytesPcodeThread(name, this) {
					TraceThread thread = trace.getThreadManager().getLiveThreadByPath(snap, name);
					PcodeExecutor<Pair<byte[], ValueLocation>> inspector =
						new PcodeExecutor<>(language,
							new PairedPcodeArithmetic<>(arithmetic,
								LocationPcodeArithmetic.forEndian(language.isBigEndian())),
							state.paired(new LocationPcodeExecutorStatePiece(language)),
							Reason.INSPECT);

					{
						tableDialog.add(createRow());
					}

					@Override
					public void stepInstruction() {
						super.stepInstruction();
						position = position.steppedForward(thread, 1);
						tableDialog.add(createRow());
					}

					@Override
					public void stepPcodeOp() {
						super.stepPcodeOp();
						position = position.steppedPcodeForward(thread, 1);
						tableDialog.add(createRow());
					}

					public CheckRow createRow() {
						List<Pair<byte[], ValueLocation>> values = new ArrayList<>();
						for (PcodeExpression exp : compiled) {
							values.add(exp.evaluate(inspector));
						}
						return new CheckRow(position, getCounter(), values);
					}
				};
			}
		};

		for (SleighPcodeUseropDefinition<?> inject : new Injects().generate().values()) {
			String source = inject.getBody();
			println("Injecting " + inject.getName() + ":\n" + source);
			for (Symbol sym : currentProgram.getSymbolTable()
					.getExternalSymbols(inject.getName())) {
				if (sym.getObject() instanceof Function fun) {
					Set<Address> addresses =
						new HashSet<>(List.of(fun.getFunctionThunkAddresses(true)));
					addresses.add(fun.getEntryPoint());
					for (Address sEntry : addresses) {
						Address dEntry = translateStaticToDynamic(sEntry);
						println("  " + sEntry + " ( -> " + dEntry + ")");
						emu.inject(dEntry, source);
					}
				}
			}
		}

		schedule.execute(trace, emu, monitor);
	}

	///////////////////////////////////////////
	// Configuration and support kruft below //
	///////////////////////////////////////////

	public record Watch(String expression, TypeRec type, Settings settings) {
	}

	interface Setting {
		void set(Settings settings);
	}

	public record EnumSetting(EnumSettingsDefinition def, int value) implements Setting {
		@Override
		public void set(Settings settings) {
			def.setChoice(settings, value);
		}
	}

	class TypeLoader extends StructuredSleigh {
		protected TypeLoader(Program program) {
			super(program);
		}

		@Override
		protected DataType type(String path) {
			return super.type(path);
		}
	}

	public record TypeRec(String path) {
		DataType get(TypeLoader loader) {
			return loader.type(path);
		}
	}

	TypeRec type(String path) {
		return new TypeRec(path);
	}

	static Setting set(EnumSettingsDefinition def, int value) {
		return new EnumSetting(def, value);
	}

	static Watch watch(String expression, TypeRec type, Setting... settings) {
		Settings settingsImpl = new SettingsImpl();
		for (Setting set : settings) {
			set.set(settingsImpl);
		}
		return new Watch(expression, type, settingsImpl);
	}

	class CheckRow implements AddressableRowObject {
		private final TraceSchedule schedule;
		private final Address pc;
		private final List<Pair<byte[], ValueLocation>> values;

		public CheckRow(TraceSchedule schedule, Address pc,
				List<Pair<byte[], ValueLocation>> values) {
			this.schedule = schedule;
			this.pc = pc;
			this.values = values;
		}

		@Override
		public Address getAddress() { // Instruction address
			TraceProgramView view = getCurrentView();
			if (view == null) {
				return Address.NO_ADDRESS;
			}
			Address st = translateDynamicToStatic(pc);
			return st == null ? Address.NO_ADDRESS : st;
		}
	}

	public interface TypedDisplay<R, T> extends ColumnDisplay<T> {
		int compareTyped(R r1, R r2);

		@Override
		@SuppressWarnings("unchecked")
		default int compare(AddressableRowObject o1, AddressableRowObject o2) {
			return compareTyped((R) o1, (R) o2);
		}

		T getTypedValue(R r);

		@Override
		@SuppressWarnings("unchecked")
		default T getColumnValue(AddressableRowObject rowObject) {
			return getTypedValue((R) rowObject);
		}
	}

	public class CheckRowScheduleDisplay implements TypedDisplay<CheckRow, TraceSchedule> {
		@Override
		public int compareTyped(CheckRow r1, CheckRow r2) {
			return r1.schedule.compareTo(r2.schedule);
		}

		@Override
		public TraceSchedule getTypedValue(CheckRow row) {
			return row.schedule;
		}

		@Override
		public String getColumnName() {
			return "Schedule";
		}

		@Override
		public Class<TraceSchedule> getColumnClass() {
			return TraceSchedule.class;
		}
	}

	public class CheckRowCounterDisplay implements TypedDisplay<CheckRow, Address> {
		@Override
		public int compareTyped(CheckRow r1, CheckRow r2) {
			return r1.pc.compareTo(r2.pc);
		}

		@Override
		public Address getTypedValue(CheckRow row) {
			return row.pc;
		}

		@Override
		public String getColumnName() {
			return "Counter";
		}

		@Override
		public Class<Address> getColumnClass() {
			return Address.class;
		}
	}

	public class CheckRowWatchDisplay implements TypedDisplay<CheckRow, Object> {
		private final boolean isBigEndian = currentProgram.getLanguage().isBigEndian();
		private final Watch watch;
		private final DataType type;
		private final int index;
		private final Class<?> valueClass;

		public CheckRowWatchDisplay(TypeLoader loader, Watch watch, int index) {
			this.watch = watch;
			this.type = watch.type.get(loader);
			this.index = index;
			this.valueClass = type.getValueClass(watch.settings);
		}

		private Object getObjectValue(CheckRow r) {
			try {
				Pair<byte[], ValueLocation> p = r.values.get(index);
				Address addr = p.getRight() == null ? null : p.getRight().getAddress();
				byte[] bytes = p.getLeft();
				return type.getValue(new ByteMemBufferImpl(addr, bytes, isBigEndian),
					watch.settings, bytes.length);
			}
			catch (Exception e) {
				return "Err: " + e.getMessage();
			}
		}

		private String getStringValue(CheckRow r) {
			try {
				Pair<byte[], ValueLocation> p = r.values.get(index);
				Address addr = p.getRight() == null ? null : p.getRight().getAddress();
				byte[] bytes = p.getLeft();
				return type.getRepresentation(new ByteMemBufferImpl(addr, bytes, isBigEndian),
					watch.settings, bytes.length);
			}
			catch (Exception e) {
				return "Err: " + e.getMessage();
			}
		}

		@Override
		@SuppressWarnings({ "unchecked", "rawtypes" })
		public int compareTyped(CheckRow r1, CheckRow r2) {
			if (Comparable.class.isAssignableFrom(valueClass)) {
				Object v1 = getObjectValue(r1);
				Object v2 = getObjectValue(r2);
				return ((Comparable) v1).compareTo(v2);
			}
			String s1 = getStringValue(r1);
			String s2 = getStringValue(r2);
			return s1.compareTo(s2);
		}

		@Override
		public String getTypedValue(CheckRow row) {
			return getStringValue(row);
		}

		@Override
		public String getColumnName() {
			return watch.expression;
		}

		@Override
		@SuppressWarnings("unchecked")
		public Class<Object> getColumnClass() {
			return (Class<Object>) valueClass;
		}
	}

	private final class CheckRowChooser implements TableChooserExecutor {
		@Override
		public String getButtonName() {
			return "Go To";
		}

		@Override
		public boolean execute(AddressableRowObject rowObject) {
			CheckRow row = (EmuDeskCheckScript.CheckRow) rowObject;
			try {
				emulate(row.schedule, monitor);
			}
			catch (CancelledException e) {
				// Just be done
			}
			return false;
		}
	}
}
