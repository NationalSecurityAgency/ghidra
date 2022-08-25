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
package ghidra.app.plugin.core.debug.gui.time;

import java.awt.BorderLayout;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.MessageType;
import ghidra.util.Msg;

public class DebuggerTimeSelectionDialog extends DialogComponentProvider {

	private final PluginTool tool;

	DebuggerSnapshotTablePanel snapshotPanel;
	JTextField scheduleText;
	TraceSchedule schedule;

	JButton tickStep;
	JButton tickBack;
	JButton opStep;
	JButton opBack;

	public DebuggerTimeSelectionDialog(PluginTool tool) {
		super("Select Time", true, true, true, false);
		this.tool = tool;
		populateComponents();
	}

	protected void doStep(Function<TraceSchedule, TraceSchedule> stepper) {
		try {
			TraceSchedule stepped = stepper.apply(schedule);
			if (stepped == null) {
				return;
			}
			setScheduleText(stepped.toString());
		}
		catch (Throwable e) {
			Msg.warn(this, e.getMessage());
		}
	}

	protected void populateComponents() {
		JPanel workPanel = new JPanel(new BorderLayout());

		{
			Box hbox = Box.createHorizontalBox();
			hbox.setBorder(BorderFactory.createTitledBorder("Schedule"));
			hbox.add(new JLabel("Expression: "));
			scheduleText = new JTextField();
			hbox.add(scheduleText);
			hbox.add(new JLabel("Ticks: "));
			hbox.add(tickBack = new JButton(DebuggerResources.ICON_STEP_BACK));
			hbox.add(tickStep = new JButton(DebuggerResources.ICON_STEP_INTO));
			hbox.add(new JLabel("Ops: "));
			hbox.add(opBack = new JButton(DebuggerResources.ICON_STEP_BACK));
			hbox.add(opStep = new JButton(DebuggerResources.ICON_STEP_INTO));
			workPanel.add(hbox, BorderLayout.NORTH);
		}

		tickBack.addActionListener(evt -> doStep(s -> s.steppedBackward(getTrace(), 1)));
		tickStep.addActionListener(evt -> doStep(s -> s.steppedForward(null, 1)));
		opBack.addActionListener(evt -> doStep(s -> s.steppedPcodeBackward(1)));
		opStep.addActionListener(evt -> doStep(s -> s.steppedPcodeForward(null, 1)));

		{
			snapshotPanel = new DebuggerSnapshotTablePanel(tool);
			workPanel.add(snapshotPanel, BorderLayout.CENTER);
		}

		snapshotPanel.getSelectionModel().addListSelectionListener(evt -> {
			Long snap = snapshotPanel.getSelectedSnapshot();
			if (snap == null) {
				return;
			}
			if (schedule.getSnap() == snap.longValue()) {
				return;
			}
			scheduleText.setText(snap.toString());
		});

		scheduleText.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				scheduleTextChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				scheduleTextChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				scheduleTextChanged();
			}
		});

		addWorkPanel(workPanel);
		addOKButton();
		addCancelButton();

		setMinimumSize(600, 600);
	}

	protected void scheduleTextChanged() {
		schedule = null;
		try {
			schedule = TraceSchedule.parse(scheduleText.getText());
			snapshotPanel.setSelectedSnapshot(schedule.getSnap());
			schedule.validate(getTrace());
			setStatusText("");
			setOkEnabled(true);
		}
		catch (Exception e) {
			setStatusText(e.getMessage(), MessageType.ERROR);
			setOkEnabled(false);
		}
		enableStepButtons(schedule != null);
	}

	protected void enableStepButtons(boolean enabled) {
		tickBack.setEnabled(enabled);
		tickStep.setEnabled(enabled);
		opBack.setEnabled(enabled);
		opStep.setEnabled(enabled);
	}

	@Override // Public for test access
	public void okCallback() {
		assert schedule != null;
		super.okCallback();
		close();
	}

	@Override // Public for test access
	public void cancelCallback() {
		this.schedule = null;
		super.cancelCallback();
	}

	@Override
	public void close() {
		super.close();
		snapshotPanel.setTrace(null);
		snapshotPanel.setSelectedSnapshot(null);
	}

	/**
	 * Prompts the user to select a snapshot and optionally specify a full schedule
	 * 
	 * @param trace the trace from whose snapshots to select
	 * @param defaultTime, optionally the time to select initially
	 * @return the schedule, likely specifying just the snapshot selection
	 */
	public TraceSchedule promptTime(Trace trace, TraceSchedule defaultTime) {
		snapshotPanel.setTrace(trace);
		schedule = defaultTime;
		scheduleText.setText(defaultTime.toString());
		tool.showDialog(this);
		return schedule;
	}

	public Trace getTrace() {
		return snapshotPanel.getTrace();
	}

	public void setScheduleText(String text) {
		scheduleText.setText(text);
	}
}
