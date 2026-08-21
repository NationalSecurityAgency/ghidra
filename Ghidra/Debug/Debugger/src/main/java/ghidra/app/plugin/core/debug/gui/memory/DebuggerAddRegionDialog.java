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

import java.awt.Font;
import java.util.Set;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import db.Transaction;
import docking.ReusableDialogComponentProvider;
import docking.widgets.model.GAddressRangeField;
import docking.widgets.model.GSpanField;
import ghidra.app.plugin.core.debug.utils.MiscellaneousUtils;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.util.layout.PairLayout;

public class DebuggerAddRegionDialog extends ReusableDialogComponentProvider {
	private Trace trace;

	private final JTextField fieldPath = new JTextField();
	private final GAddressRangeField fieldRange = new GAddressRangeField();
	private final JTextField fieldLength = new JTextField();
	private final GSpanField fieldLifespan = new GSpanField();
	// NOTE: Flags can be toggled in table

	public DebuggerAddRegionDialog() {
		super("Add Region", true, true, true, false);

		populateComponents();
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new PairLayout(5, 5));

		panel.setBorder(new EmptyBorder(10, 10, 10, 10));

		panel.add(new JLabel("Path: "));
		panel.add(fieldPath);

		panel.add(new JLabel("Range: "));
		fieldRange.getAccessibleContext().setAccessibleName("Range");
		panel.add(fieldRange);

		panel.add(new JLabel("Length: "));
		fieldLength.setFont(Font.decode("monospaced"));
		fieldLength.getAccessibleContext().setAccessibleName("Length");
		panel.add(fieldLength);

		panel.add(new JLabel("Lifespan: "));
		fieldLifespan.getAccessibleContext().setAccessibleName("Lifespan");
		panel.add(fieldLifespan);

		MiscellaneousUtils.rigFocusAndEnter(fieldRange, this::rangeChanged);
		MiscellaneousUtils.rigFocusAndEnter(fieldLength, this::lengthChanged);

		fieldLifespan.setLifespan(Lifespan.nowOn(0));
		panel.getAccessibleContext().setAccessibleName("Debugger Region Addition");
		addWorkPanel(panel);

		addOKButton();
		addCancelButton();
	}

	protected static AddressRange range(Address min, long lengthMinus1) {
		return new AddressRangeImpl(min, min.addWrap(lengthMinus1));
	}

	public void setPath(String path) {
		fieldPath.setText(path);
	}

	protected void setFieldLength(long length) {
		fieldLength.setText(MiscellaneousUtils.lengthToString(length));
	}

	public long getLength() {
		return MiscellaneousUtils.parseLength(fieldLength.getText(), 1);
	}

	protected void revalidateLength() {
		long length;
		if (fieldLength.getText().trim().startsWith("-")) {
			length = 1;
		}
		else {
			length = getLength();
		}
		length = MiscellaneousUtils.revalidateLengthByRange(fieldRange.getRange(), length);
		setFieldLength(length);
	}

	protected void adjustLengthToRange() {
		AddressRange range = fieldRange.getRange();
		if (range == null) {
			return;
		}
		long length = range.getLength();
		setFieldLength(length);
	}

	protected void adjustRangeToLength() {
		AddressRange range = fieldRange.getRange();
		if (range == null) {
			return;
		}
		Address min = range.getMinAddress();
		fieldRange.setRange(range(min, getLength() - 1));
	}

	protected void rangeChanged() {
		adjustLengthToRange();
	}

	protected void lengthChanged() {
		revalidateLength();
		adjustRangeToLength();
	}

	@Override
	protected void dialogShown() {
		super.dialogShown();
		setStatusText("");
	}

	@Override
	protected void cancelCallback() {
		setStatusText("");
		super.cancelCallback();
	}

	@Override
	protected void okCallback() {
		addRegionAndClose();
	}

	protected String computeDefaultPath(DebuggerCoordinates current) {
		TraceObjectSchema rootSchema = trace.getObjectManager().getRootSchema();
		if (rootSchema == null) {
			return "";
		}
		KeyPath suitable =
			rootSchema.searchForSuitableContainer(TraceMemoryRegion.class, current.getPath());
		if (suitable == null) {
			return "";
		}

		return suitable.index("New").toString();
	}

	protected void setValues(DebuggerCoordinates current) {
		this.trace = current.getTrace();
		AddressFactory af = trace.getBaseAddressFactory();
		this.fieldRange.setAddressFactory(af);
		this.fieldRange.setRange(range(af.getDefaultAddressSpace().getAddress(0), 0));
		this.fieldLength.setText("0x1");
		Lifespan lifespan = Lifespan.nowOn(current.getSnap());
		this.fieldLifespan.setLifespan(lifespan);
		this.fieldPath.setText(computeDefaultPath(current));
	}

	public void show(PluginTool tool, DebuggerCoordinates current) {
		setValues(current);
		tool.showDialog(this);
	}

	@Override
	public void close() {
		trace = null;
		fieldRange.setAddressFactory(null);
		super.close();
	}

	protected void addRegionAndClose() {
		try (Transaction tx = trace.openTransaction("Add region: " + fieldPath)) {
			trace.getMemoryManager()
					.addRegion(
						fieldPath.getText(),
						fieldLifespan.getLifespan(), fieldRange.getRange(),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE,
							TraceMemoryFlag.EXECUTE));
			close();
		}
		catch (Exception e) {
			setStatusText(e.getMessage());
		}
	}
}
