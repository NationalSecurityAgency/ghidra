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
package ghidra.symz3.gui;

import java.awt.BorderLayout;
import java.util.Objects;

import javax.swing.*;

import com.microsoft.z3.Context;

import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceLocationPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerEmulationService.CachedEmulator;
import ghidra.app.services.DebuggerEmulationService.EmulatorStateListener;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.util.pcode.StringPcodeFormatter;
import ghidra.debug.api.emulation.DebuggerPcodeEmulatorFactory;
import ghidra.debug.api.emulation.DebuggerPcodeMachine;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.pcode.emu.symz3.full.SymZ3DebuggerPcodeEmulator;
import ghidra.pcode.emu.symz3.full.SymZ3DebuggerPcodeEmulatorFactory;
import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class Z3SummaryProvider extends ComponentProviderAdapter {

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false;
		}
		return true;
	}

	private final EmulatorStateListener emuListener = new EmulatorStateListener() {
		@Override
		public void stopped(CachedEmulator emu) {
			if (!(emu.emulator() instanceof SymZ3DebuggerPcodeEmulator z3emu)) {
				setFactoryToZ3();
				return;
			}
			populateSummaryFromEmulator(z3emu);
		}
	};

	@SuppressWarnings("unused")
	private final Z3SummaryPlugin plugin;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	//@AutoServiceConsumed via method
	private DebuggerEmulationService emulationService;
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	@SuppressWarnings("unused")
	private AutoOptions.Wiring autoOptionsWiring;

	String style = "<html>";

	JPanel mainPanel = new JPanel(new BorderLayout());
	JSplitPane submainPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
	JSplitPane codePanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

	Z3SummaryInformationPanel information;
	Z3SummaryPcodeLogPanel ops;
	Z3SummaryInstructionLogPanel instructions;

	StringPcodeFormatter formatter = new StringPcodeFormatter();

	public Z3SummaryProvider(Z3SummaryPlugin plugin) {
		super(plugin.getTool(), "Z3 Summary", plugin.getName(), null);
		this.plugin = plugin;
		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		this.autoOptionsWiring = AutoOptions.wireOptions(plugin, this);
		setIcon(DebuggerResources.ICON_PROVIDER_PCODE);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_PCODE);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);
		buildMainPanel();
		setVisible(true);
		contextChanged();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private void buildMainPanel() {
		information = new Z3SummaryInformationPanel(this);
		ops = new Z3SummaryPcodeLogPanel(this);
		instructions = new Z3SummaryInstructionLogPanel(this);

		JPanel summaryPanel = new JPanel(new BorderLayout());
		summaryPanel.add(new JScrollPane(information));
		codePanel.setTopComponent(instructions);
		codePanel.setBottomComponent(ops);
		codePanel.setDividerLocation(0.4);
		submainPanel.setRightComponent(summaryPanel);
		submainPanel.setLeftComponent(codePanel);
		mainPanel.add(submainPanel);
	}

	public void updateSummary() {
		ops.setLog(java.util.List.of());
		instructions.setLog(java.util.List.of());

		if (emulationService == null) {
			return;
		}

		Trace trace = current.getTrace();
		if (trace == null) {
			return;
		}

		TraceSchedule time = current.getTime();
		DebuggerPcodeMachine<?> emu = emulationService.getCachedEmulator(trace, time);
		if (!(emu instanceof SymZ3DebuggerPcodeEmulator z3Emu)) {
			/** LATER: It'd be nice if the summary were written down somewhere */
			setFactoryToZ3();
			return;
		}

		populateSummaryFromEmulator(z3Emu);
	}

	private void setFactoryToZ3() {
		for (DebuggerPcodeEmulatorFactory factory : emulationService.getEmulatorFactories()) {
			if (factory instanceof SymZ3DebuggerPcodeEmulatorFactory z3factory) {
				emulationService.setEmulatorFactory(z3factory);
				emulationService.invalidateCache();
				return;
			}
		}
	}

	public void populateSummaryFromEmulator(SymZ3DebuggerPcodeEmulator emu) {
		try (Context ctx = new Context()) {
			Z3InfixPrinter z3p = new Z3InfixPrinter(ctx);
			information.setInformation(emu.streamValuations(ctx, z3p),
				emu.streamPreconditions(ctx, z3p));
		}
		ops.setLog(emu.getOps());
		instructions.setLog(emu.getInstructions());
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		current = coordinates;
		updateSummary();
		setSubTitle(current.getTime().toString());
		contextChanged();
	}

	public void fireAddress(Address address) {
		plugin.firePluginEvent(new TraceLocationPluginEvent(plugin.getName(),
			new ProgramLocation(current.getView(), address)));
	}

	@AutoServiceConsumed
	private void setEmulationService(DebuggerEmulationService emulationService) {
		if (this.emulationService != null) {
			this.emulationService.removeStateListener(emuListener);
		}
		this.emulationService = emulationService;
		if (this.emulationService != null) {
			this.emulationService.addStateListener(emuListener);
		}
	}
}
