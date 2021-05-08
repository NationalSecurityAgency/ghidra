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
package ghidra.app.plugin.core.debug.gui.modules;

import java.awt.Component;
import java.awt.Font;
import java.awt.event.*;
import java.math.BigInteger;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import com.google.common.collect.Range;

import docking.DialogComponentProvider;
import docking.widgets.model.GAddressRangeField;
import docking.widgets.model.GLifespanField;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.modules.TraceConflictedMappingException;
import ghidra.util.MathUtilities;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.layout.PairLayout;

public class DebuggerAddMappingDialog extends DialogComponentProvider {
	private static final String HEX_BIT64 = "0x" + BigInteger.ONE.shiftLeft(64).toString(16);

	private DebuggerStaticMappingService mappingService;

	private Program program;
	private Trace trace;

	private final JLabel labelProg = new JLabel();
	private final GAddressRangeField fieldProgRange = new GAddressRangeField();
	private final JLabel labelTrace = new JLabel();
	private final GAddressRangeField fieldTraceRange = new GAddressRangeField();
	private final JTextField fieldLength = new JTextField();
	private final GLifespanField fieldSpan = new GLifespanField();

	public DebuggerAddMappingDialog() {
		super("Add Static Mapping", false, false, true, false);

		populateComponents();
	}

	protected static void rigFocusAndEnter(Component c, Runnable runnable) {
		c.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				runnable.run();
			}
		});
		c.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					runnable.run();
				}
			}
		});
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new PairLayout(5, 5));

		panel.setBorder(new EmptyBorder(10, 10, 10, 10));

		panel.add(new JLabel("Program: "));
		panel.add(labelProg);

		panel.add(new JLabel("Static Range: "));
		panel.add(fieldProgRange);

		panel.add(new JLabel("Trace: "));
		panel.add(labelTrace);

		panel.add(new JLabel("Dynamic Range: "));
		panel.add(fieldTraceRange);

		panel.add(new JLabel("Length: "));
		fieldLength.setFont(Font.decode("monospaced"));
		panel.add(fieldLength);

		panel.add(new JLabel("Lifespan: "));
		panel.add(fieldSpan);

		rigFocusAndEnter(fieldProgRange, this::progRangeChanged);
		rigFocusAndEnter(fieldTraceRange, this::traceRangeChanged);
		rigFocusAndEnter(fieldLength, this::lengthChanged);
		rigFocusAndEnter(fieldSpan, this::spanChanged);

		addWorkPanel(panel);

		addApplyButton();
		addDismissButton();
		setDefaultButton(null);
	}

	public void setMappingService(DebuggerStaticMappingService mappingService) {
		this.mappingService = mappingService;
	}

	protected static void revalidateByLength(GAddressRangeField adjusted,
			GAddressRangeField other) {
		AddressRange adjRange = adjusted.getRange();
		if (adjRange == null) {
			return;
		}
		long lengthMinus1 = adjRange.getMaxAddress().subtract(adjRange.getMinAddress());
		AddressRange otherRange = other.getRange();
		if (otherRange == null) {
			return;
		}
		long maxLengthMinus1 =
			otherRange.getAddressSpace().getMaxAddress().subtract(otherRange.getMinAddress());
		if (Long.compareUnsigned(lengthMinus1, maxLengthMinus1) > 0) {
			adjusted.setRange(range(adjRange.getMinAddress(), maxLengthMinus1));
		}
	}

	protected void revalidateProgRange() {
		/**
		 * Not sure there's much to do here wrt/ the program. Might be nice to warn (but not
		 * prohibit) when range is not in memory. NB: A range spanning all blocks will likely
		 * contain some dead space.
		 */
		revalidateByLength(fieldProgRange, fieldTraceRange);
	}

	protected void revalidateTraceRange() {
		// Similarly nothing to really do wrt/ the trace.
		revalidateByLength(fieldTraceRange, fieldProgRange);
	}

	protected static long lengthMin(long a, long b) {
		if (a == 0) {
			return b;
		}
		if (b == 0) {
			return a;
		}
		return MathUtilities.unsignedMin(a, b);
	}

	protected static long revalidateLengthByRange(AddressRange range, long length) {
		long maxLength =
			range.getAddressSpace().getMaxAddress().subtract(range.getMinAddress()) + 1;
		return lengthMin(length, maxLength);
	}

	protected void setFieldLength(long length) {
		if (length == 0) {
			fieldLength.setText(HEX_BIT64);
		}
		else {
			fieldLength.setText("0x" + Long.toHexString(length));
		}
	}

	public long getLength() {
		return parseLength(fieldLength.getText(), 1);
	}

	protected void revalidateLength() {
		long length;
		if (fieldLength.getText().trim().startsWith("-")) {
			length = 1;
		}
		else {
			length = getLength();
		}
		length = revalidateLengthByRange(fieldProgRange.getRange(), length);
		length = revalidateLengthByRange(fieldTraceRange.getRange(), length);
		setFieldLength(length);
	}

	protected void revalidateSpan() {
		// Yeah, nothing to do
	}

	protected static AddressRange range(Address min, long lengthMinus1) {
		return new AddressRangeImpl(min, min.addWrap(lengthMinus1));
	}

	protected void adjustLengthToProgRange() {
		long length = fieldProgRange.getRange().getLength();
		setFieldLength(length);
	}

	protected void adjustLengthToTraceRange() {
		long length = fieldTraceRange.getRange().getLength();
		setFieldLength(length);
	}

	protected void adjustRangeToLength(GAddressRangeField field) {
		AddressRange range = field.getRange();
		if (range == null) {
			return;
		}
		Address min = range.getMinAddress();
		field.setRange(range(min, getLength() - 1));
	}

	protected void adjustProgRangeToLength() {
		adjustRangeToLength(fieldProgRange);
	}

	protected void adjustTraceRangeToLength() {
		adjustRangeToLength(fieldTraceRange);
	}

	protected void progRangeChanged() {
		revalidateProgRange();
		adjustLengthToProgRange();
		adjustTraceRangeToLength();
	}

	protected void traceRangeChanged() {
		revalidateTraceRange();
		adjustLengthToTraceRange();
		adjustProgRangeToLength();
	}

	protected void lengthChanged() {
		revalidateLength();
		adjustProgRangeToLength();
		adjustTraceRangeToLength();
	}

	protected void spanChanged() {
		revalidateSpan();
	}

	/**
	 * Parses a value from 1 to 1<<64. Any value outside the range is "clipped" into the range.
	 * 
	 * <p>
	 * Note that a returned value of 0 indicates 2 to the power 64, which is just 1 too high to fit
	 * into a 64-bit long.
	 * 
	 * @param text the text to parse
	 * @param defaultVal the default value should parsing fail altogether
	 * @return the length, where 0 indicates {@code 1 << 64}.
	 */
	protected static long parseLength(String text, long defaultVal) {
		text = text.trim();
		String post;
		int radix;
		if (text.startsWith("-")) {
			return 0;
		}
		if (text.startsWith("0x")) {
			post = text.substring(2);
			radix = 16;
		}
		else {
			post = text;
			radix = 10;
		}
		BigInteger bi;
		try {
			bi = new BigInteger(post, radix);
		}
		catch (NumberFormatException e) {
			return defaultVal;
		}
		if (bi.equals(BigInteger.ZERO)) {
			return 1;
		}
		if (bi.bitLength() > 64) {
			return 0; // indicates 2**64, the max length
		}
		return bi.longValue(); // Do not use exact. It checks bitLength again, and considers sign.
	}

	@Override
	protected void applyCallback() {
		TraceLocation from = new DefaultTraceLocation(trace, null, fieldSpan.getLifespan(),
			fieldTraceRange.getRange().getMinAddress());
		ProgramLocation to = new ProgramLocation(program,
			fieldProgRange.getRange().getMinAddress());

		try (UndoableTransaction tid =
			UndoableTransaction.start(trace, "Add Static Mapping", false)) {
			mappingService.addMapping(from, to, getLength(), true);
			tid.commit();
		}
		catch (TraceConflictedMappingException e) {
			throw new AssertionError(e); // I said truncateExisting
		}
	}

	/**
	 * Set the values of the fields
	 * 
	 * @param program the program
	 * @param trace the trace
	 * @param progStart the starting static address
	 * @param traceStart the starting dynamic address
	 * @param length the length (0 indicates the entire 64-bit range)
	 * @param lifespan the lifespan
	 * @throws AddressOverflowException if the length is too large for either space
	 */
	public void setValues(Program program, Trace trace, Address progStart,
			Address traceStart, long length, Range<Long> lifespan) throws AddressOverflowException {
		// NB. This dialog will not validate these. The caller is responsible.
		this.program = program;
		this.trace = trace;
		this.fieldProgRange.setAddressFactory(program.getAddressFactory());
		this.fieldProgRange.setRange(range(progStart, length - 1));
		this.fieldTraceRange.setAddressFactory(trace.getBaseAddressFactory());
		this.fieldTraceRange.setRange(range(traceStart, length - 1));
		setFieldLength(length);
		this.fieldSpan.setLifespan(lifespan);
	}

	protected void setEnabled(boolean enabled) {
		applyButton.setEnabled(enabled);
		fieldProgRange.setEnabled(enabled);
		fieldTraceRange.setEnabled(enabled);
		fieldLength.setEnabled(enabled);
		fieldSpan.setEnabled(enabled);
	}

	public void setTrace(Trace trace) {
		this.trace = trace;
		if (trace != null) {
			labelTrace.setText(trace.getName());
			fieldTraceRange.setAddressFactory(trace.getBaseAddressFactory());
		}
		else {
			labelTrace.setText("[No Trace]");
			fieldTraceRange.setAddressFactory(null);
		}
		if (program != null && trace != null) {
			traceRangeChanged();
			setEnabled(true);
		}
		else {
			setEnabled(false);
		}
	}

	public void setProgram(Program program) {
		this.program = program;
		if (program != null) {
			labelProg.setText(program.getName());
			fieldProgRange.setAddressFactory(program.getAddressFactory());
		}
		else {
			labelProg.setText("[No Program]");
			fieldProgRange.setAddressFactory(null);
		}
		if (program != null && trace != null) {
			progRangeChanged();
			setEnabled(true);
		}
		else {
			setEnabled(false);
		}
	}
}
