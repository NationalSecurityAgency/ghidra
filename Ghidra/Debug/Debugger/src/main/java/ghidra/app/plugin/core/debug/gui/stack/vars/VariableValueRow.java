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
package ghidra.app.plugin.core.debug.gui.stack.vars;

import static ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueRow.*;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.core.debug.stack.UnwoundFrame;
import ghidra.pcode.exec.DebuggerPcodeUtils.PrettyBytes;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.pcode.exec.ValueLocation;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Varnode;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.TraceCodeUnit;
import ghidra.trace.model.memory.*;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.InvalidInputException;

/**
 * A row to be displayed in a variable value hover's table
 */
public interface VariableValueRow {
	// TODO: Colors specific to hovers?
	GColor COLOR_ERROR = Colors.ERROR;
	GColor COLOR_STALE = new GColor("color.fg.debugger.value.stale");

	/**
	 * Perform the simplest styling of the object
	 * 
	 * <p>
	 * This merely invokes the object's {@link Object#toString()} method and escapes its. If it's
	 * null, it will render "None" is the error color.
	 * 
	 * @param obj the object, possibly null
	 * @return the HTML-styled string
	 */
	static String styleSimple(Object obj) {
		return obj == null ? htmlFg(COLOR_ERROR, "None") : HTMLUtilities.escapeHTML(obj.toString());
	}

	/**
	 * Style a given string according to the given memory state
	 * 
	 * <p>
	 * This renders stale ({@link TraceMemoryState#UNKNOWN}) values in the stale color, usually
	 * gray.
	 * 
	 * @param state the state
	 * @param str the HTML string
	 * @return the HTML-styled string
	 */
	static String styleState(TraceMemoryState state, String str) {
		if (state == TraceMemoryState.KNOWN) {
			return str;
		}
		return "<font color='" + COLOR_STALE.toHexString() + "'>" + str + "</font>";
	}

	/**
	 * Escape and style the given text in the given color
	 * 
	 * @param color the color
	 * @param text the text
	 * @return the HTML-styled string
	 */
	static String htmlFg(GColor color, String text) {
		return "<font color='" + color.toHexString() + "'>" + HTMLUtilities.escapeHTML(text) +
			"</font>";
	}

	/**
	 * A key naming a given row type
	 * 
	 * <p>
	 * This ensures the rows always appear in conventional order, and that there is only one of
	 * each.
	 */
	enum RowKey {
		NAME("Name"),
		FRAME("Frame"),
		STORAGE("Storage"),
		TYPE("Type"),
		INSTRUCTION("Instruction"),
		LOCATION("Location"),
		BYTES("Bytes"),
		INTEGER("Integer"),
		VALUE("Value"),
		STATUS("Status"),
		WARNINGS("Warnings"),
		ERROR("Error"),
		;

		private final String display;

		RowKey(String display) {
			this.display = display;
		}

		@Override
		public String toString() {
			return display;
		}
	}

	/**
	 * Get the key for this row type
	 * 
	 * @return the key
	 */
	RowKey key();

	/**
	 * Render the key for display in diagnostics
	 * 
	 * @return the the key as a string
	 */
	default String keyToSimpleString() {
		return key().toString();
	}

	/**
	 * Render the key for display in the table
	 * 
	 * @return the key as an HTML string
	 */
	default String keyToHtml() {
		return HTMLUtilities.escapeHTML(key() + ":");
	}

	/**
	 * Render the value for display in diagnostics
	 * 
	 * @return the value as a string
	 */
	String valueToSimpleString();

	/**
	 * Render the value for display in the table
	 * 
	 * @return the value as an HTML string
	 */
	String valueToHtml();

	/**
	 * Render this complete row for display in diagnostics
	 * 
	 * @return the row as a string
	 */
	default String toSimpleString() {
		return String.format("%s: %s", keyToSimpleString(), valueToSimpleString());
	}

	/**
	 * Render this complete row for display in the table
	 * 
	 * @return the row as an HTMl string
	 */
	default String toHtml() {
		return String.format("<tr><td valign='top'><b>%s</b></td><td><tt>%s</tt></td></tr>",
			keyToHtml(), valueToHtml());
	}

	/**
	 * A row for the variable's name
	 */
	record NameRow(String name) implements VariableValueRow {
		@Override
		public RowKey key() {
			return RowKey.NAME;
		}

		@Override
		public String valueToHtml() {
			return styleSimple(name);
		}

		@Override
		public String valueToSimpleString() {
			return name;
		}
	}

	/**
	 * A row for the frame used to compute the location and value
	 */
	record FrameRow(UnwoundFrame<?> frame) implements VariableValueRow {
		@Override
		public RowKey key() {
			return RowKey.FRAME;
		}

		@Override
		public String valueToHtml() {
			return styleSimple(frame.getDescription());
		}

		@Override
		public String valueToSimpleString() {
			return frame.getDescription();
		}
	}

	/**
	 * A row for the variable's statically-defined storage
	 */
	record StorageRow(VariableStorage storage) implements VariableValueRow {
		public static StorageRow fromCodeUnit(CodeUnit unit) {
			try {
				return new StorageRow(new VariableStorage(unit.getProgram(),
					new Varnode(unit.getMinAddress(), unit.getLength())));
			}
			catch (InvalidInputException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public RowKey key() {
			return RowKey.STORAGE;
		}

		@Override
		public String valueToHtml() {
			return styleSimple(storage);
		}

		@Override
		public String valueToSimpleString() {
			return storage.toString();
		}
	}

	/**
	 * A row for the variable's type
	 */
	record TypeRow(DataType type) implements VariableValueRow {
		@Override
		public RowKey key() {
			return RowKey.TYPE;
		}

		@Override
		public String valueToHtml() {
			return styleSimple(type.getDisplayName());
		}

		@Override
		public String valueToSimpleString() {
			return type.getDisplayName();
		}
	}

	/**
	 * If an operand refers to code, a row for the target instruction
	 */
	record InstructionRow(Instruction instruction) implements VariableValueRow {
		@Override
		public RowKey key() {
			return RowKey.INSTRUCTION;
		}

		@Override
		public String valueToHtml() {
			return styleSimple(instruction);
		}

		@Override
		public String valueToSimpleString() {
			return instruction.toString();
		}
	}

	/**
	 * A row for the variable's dynamic location
	 */
	record LocationRow(String locString) implements VariableValueRow {
		/**
		 * Create a row from the given range
		 * 
		 * @param range the range
		 * @return the row
		 */
		public static LocationRow fromRange(AddressRange range) {
			return new LocationRow(
				String.format("%s:%d", range.getMinAddress(), range.getLength()));
		}

		/**
		 * Create a row from the given code unit
		 * 
		 * @param unit the unit
		 * @return the row
		 */
		public static LocationRow fromCodeUnit(CodeUnit unit) {
			return new LocationRow(
				String.format("%s:%d", unit.getMinAddress(), unit.getLength()));
		}

		/***
		 * Create a row from the given watch value
		 * 
		 * @param value the value
		 * @param language the language (for register name substitution)
		 * @return the row
		 */
		public static LocationRow fromWatchValue(WatchValue value, Language language) {
			ValueLocation loc = value.location();
			if (loc == null || loc.isEmpty()) {
				return new LocationRow(null);
			}
			return new LocationRow(loc.toString(language));
		}

		@Override
		public RowKey key() {
			return RowKey.LOCATION;
		}

		@Override
		public String valueToHtml() {
			return styleSimple(locString);
		}

		@Override
		public String valueToSimpleString() {
			return locString == null ? "None" : locString;
		}
	}

	/**
	 * Compute the memory state of a given range
	 * 
	 * <p>
	 * If any part of the range is not {@link TraceMemoryState#KNOWN} the result is
	 * {@link TraceMemoryState#UNKNOWN}.
	 * 
	 * @param trace the trace
	 * @param space the thread, frame level, and address space
	 * @param range the address range
	 * @param snap the snapshot key
	 * @return the composite state
	 */
	static TraceMemoryState computeState(Trace trace, TraceAddressSpace space, AddressRange range,
			long snap) {
		TraceMemoryManager mem = trace.getMemoryManager();
		TraceMemoryOperations ops;
		if (space != null && space.getAddressSpace().isRegisterSpace()) {
			ops = mem.getMemoryRegisterSpace(space.getThread(), space.getFrameLevel(), false);
		}
		else {
			ops = mem;
		}
		return ops != null && ops.isKnown(snap, range)
				? TraceMemoryState.KNOWN
				: TraceMemoryState.UNKNOWN;
	}

	/**
	 * Compute the memory state of a given code unit
	 * 
	 * @param unit the code unit
	 * @param snap the snapshot key
	 * @return the composite state.
	 * @see #computeState(Trace, TraceAddressSpace, AddressRange, long)
	 */
	static TraceMemoryState computeState(TraceCodeUnit unit, long snap) {
		return computeState(unit.getTrace(), unit.getTraceSpace(), unit.getRange(), snap);
	}

	/**
	 * A row to display the bytes in the variable
	 */
	record BytesRow(PrettyBytes bytes, TraceMemoryState state) implements VariableValueRow {
		/**
		 * Create a row from a given range
		 * 
		 * @param platform the platform (for trace memory and language)
		 * @param range the range
		 * @param snap the snapshot key
		 * @return the row
		 */
		public static BytesRow fromRange(TracePlatform platform, AddressRange range, long snap) {
			long size = range.getLength();
			ByteBuffer buf = ByteBuffer.allocate((int) size);
			Trace trace = platform.getTrace();
			if (size != trace.getMemoryManager().getViewBytes(snap, range.getMinAddress(), buf)) {
				throw new AssertionError(new MemoryAccessException("Could not read bytes"));
			}
			return new BytesRow(
				new PrettyBytes(platform.getLanguage().isBigEndian(), buf.array()),
				computeState(trace, null, range, snap));
		}

		/**
		 * Create a row from a given code unit
		 * 
		 * @param unit unit
		 * @param snap the snapshot key
		 * @return the row
		 */
		public static BytesRow fromCodeUnit(TraceCodeUnit unit, long snap) {
			try {
				return new BytesRow(new PrettyBytes(unit.isBigEndian(), unit.getBytes()),
					computeState(unit, snap));
			}
			catch (MemoryAccessException e) {
				throw new AssertionError(e);
			}
		}

		/**
		 * Create a row from a given watch value
		 * 
		 * @param value the value
		 */
		public BytesRow(WatchValue value) {
			this(value.bytes(), value.state());
		}

		@Override
		public RowKey key() {
			return RowKey.BYTES;
		}

		@Override
		public String valueToHtml() {
			return styleState(state, bytes.toBytesString().replace("\n", "<br>"));
		}

		@Override
		public String valueToSimpleString() {
			return String.format("(%s) %s", state, bytes.toBytesString());
		}
	}

	/**
	 * A row to display a variable's value as an integer in various formats
	 */
	record IntegerRow(PrettyBytes bytes, TraceMemoryState state) implements VariableValueRow {
		/**
		 * Create a row from a given code unit
		 * 
		 * @param unit the unit
		 * @param snap the snapshot key
		 * @return the row
		 */
		public static IntegerRow fromCodeUnit(TraceCodeUnit unit, long snap) {
			try {
				return new IntegerRow(new PrettyBytes(unit.isBigEndian(), unit.getBytes()),
					computeState(unit, snap));
			}
			catch (MemoryAccessException e) {
				throw new AssertionError(e);
			}
		}

		/**
		 * Create a row from the given {@link BytesRow}
		 * 
		 * @param bytes the bytes row
		 */
		public IntegerRow(BytesRow bytes) {
			this(bytes.bytes, bytes.state);
		}

		/**
		 * Create a row from the given watch value
		 * 
		 * @param value the value
		 */
		public IntegerRow(WatchValue value) {
			this(value.bytes(), value.state());
		}

		@Override
		public RowKey key() {
			return RowKey.INTEGER;
		}

		@Override
		public String toHtml() {
			if (bytes.length() > 16) {
				return "";
			}
			return VariableValueRow.super.toHtml();
		}

		@Override
		public String valueToHtml() {
			return styleState(state, bytes.collectDisplays().replace("\n", "<br>"));
		}

		@Override
		public String valueToSimpleString() {
			return String.format("(%s) %s", state, bytes.collectDisplays());
		}
	}

	/**
	 * A row to display the variable's value in its type's default representation
	 */
	record ValueRow(String value, TraceMemoryState state) implements VariableValueRow {
		@Override
		public RowKey key() {
			return RowKey.VALUE;
		}

		@Override
		public String valueToHtml() {
			return styleState(state, HTMLUtilities.escapeHTML(value));
		}

		@Override
		public String valueToSimpleString() {
			return String.format("(%s) %s", state, value);
		}
	}

	/**
	 * A row to indicate the computation status, in case it takes a moment
	 */
	record StatusRow(String status) implements VariableValueRow {
		@Override
		public RowKey key() {
			return RowKey.STATUS;
		}

		@Override
		public String valueToHtml() {
			return String.format("<em>%s</em>", HTMLUtilities.escapeHTML(status.toString()));
		}

		@Override
		public String valueToSimpleString() {
			return status.toString();
		}
	}

	/**
	 * A row to display the warnings encountered while unwinding the frame used to evaluate the
	 * variable
	 */
	record WarningsRow(String warnings) implements VariableValueRow {
		/**
		 * Create a row from the given list of warnings
		 * 
		 * @param warnings the warnings
		 */
		public WarningsRow(List<String> warnings) {
			this(warnings.stream()
					.map(String::trim)
					.filter(w -> !w.isBlank())
					.collect(Collectors.joining("\n")));
		}

		@Override
		public RowKey key() {
			return RowKey.WARNINGS;
		}

		@Override
		public String keyToHtml() {
			return htmlFg(COLOR_ERROR, key() + ":");
		}

		@Override
		public String valueToHtml() {
			String[] split = warnings.split("\n");
			String formatted = Stream.of(split)
					.map(w -> String.format("<li>%s</li>", HTMLUtilities.escapeHTML(w)))
					.collect(Collectors.joining("\n  "));
			return String.format("""
					<ul>
					  %s
					</ul>
					""", formatted);
		}

		@Override
		public String valueToSimpleString() {
			return warnings;
		}

		@Override
		public String toHtml() {
			if (warnings.isBlank()) {
				return "";
			}
			return String.format("<tr><td valign='top'><b>%s</b></td><td>%s</td></tr>",
				keyToHtml(), valueToHtml());
		}
	}

	/**
	 * A row to display an error in case the table is incomplete
	 */
	record ErrorRow(Throwable error) implements VariableValueRow {
		@Override
		public RowKey key() {
			return RowKey.ERROR;
		}

		@Override
		public String keyToHtml() {
			return htmlFg(COLOR_ERROR, key() + ":");
		}

		@Override
		public String valueToHtml() {
			return styleSimple(error);
		}

		@Override
		public String valueToSimpleString() {
			return error.toString();
		}

		@Override
		public String toHtml() {
			return String.format("<tr><td valign='top'><b>%s</b></td><td>%s</td></tr>",
				keyToHtml(), valueToHtml());
		}
	}
}
