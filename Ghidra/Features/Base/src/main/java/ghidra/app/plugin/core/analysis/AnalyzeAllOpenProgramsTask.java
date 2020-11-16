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
package ghidra.app.plugin.core.analysis;

import java.awt.BorderLayout;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;
import javax.swing.text.html.HTMLEditorKit;

import docking.widgets.OptionDialog;
import docking.widgets.label.GLabel;
import ghidra.GhidraOptions;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.HTMLUtilities;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

class AnalyzeAllOpenProgramsTask extends Task {
	/** The program that is used for a source of analysis options */
	private final Program prototypeProgram;
	private final List<Program> programs;
	private final PluginTool tool;

	private AnalyzeProgramStrategy analyzeStrategy;
	private CancelledListener bottomUpCancelledListener;
	private CancelledListener topDownCancelledListener;

	AnalyzeAllOpenProgramsTask(Plugin plugin) {
		super("Analyzing All Open Programs", true, true, false);
		this.tool = plugin.getTool();

		ProgramManager pm = tool.getService(ProgramManager.class);
		this.prototypeProgram = pm.getCurrentProgram();
		this.programs = Arrays.asList(pm.getAllOpenPrograms());
		this.analyzeStrategy = new DefaultAnalyzeProgramStrategy();
	}

	AnalyzeAllOpenProgramsTask(PluginTool tool, Program prototypeProgram, Program[] programs,
			AnalyzeProgramStrategy strategy) {
		super("Analyzing All Open Programs", true, true, false);

		this.tool = tool;
		this.programs = Arrays.asList(programs);
		this.prototypeProgram = prototypeProgram;
		this.analyzeStrategy = strategy;
	}

	@Override
	public void run(TaskMonitor monitor) {
		if (programs.isEmpty()) {
			return;
		}

		monitor.initialize(programs.size());

		List<Program> validPrograms = null;
		AnalysisOptions prototypeAnalysisOptions = null;
		Options options = tool.getOptions(GhidraOptions.CATEGORY_AUTO_ANALYSIS);
		boolean showDialog = options.getBoolean("Show Analysis Options", true);
		if (showDialog) {
			try {
				validPrograms = checkForInvalidProgramsByArchitecture();
			}
			catch (CancelledException e) {
				return;  // no need to log this - it's a valid condition
			}

			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(prototypeProgram);
			if (!setOptions(prototypeProgram, mgr)) {
				return;
			}

			prototypeAnalysisOptions = new AnalysisOptions(prototypeProgram);
		}
		else {
			// no options dialog--analyze all programs
			validPrograms = new ArrayList<>(programs);
		}

		analyzePrograms(prototypeAnalysisOptions, validPrograms, monitor);
	}

	private void analyzePrograms(AnalysisOptions prototypeAnalysisOptions,
			List<Program> validPrograms, TaskMonitor monitor) {

		// a bottom-up cancelled listener (this is to know when the user presses cancel on the
		// tool's cancel icon, not this task's)
		bottomUpCancelledListener = new BottomUpCancelledListener(monitor);
		topDownCancelledListener = new TopDownCancelledListener();
		monitor.addCancelledListener(topDownCancelledListener);

		for (int i = 0; i < validPrograms.size(); i++) {
			if (monitor.isCancelled()) {
				break;
			}

			Program program = validPrograms.get(i);
			if (program.isClosed()) {
				monitor.setProgress(i);
				continue;
			}

			monitor.setMessage("Analyzing " + program.getName() + "...");

			int id = program.startTransaction("analysis");
			try {
				AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
				initializeAnalysisOptions(program, prototypeAnalysisOptions, manager);

				GhidraProgramUtilities.setAnalyzedFlag(program, true);

				analyzeStrategy.analyzeProgram(program, manager, monitor);
			}
			finally {
				program.endTransaction(id, true);
			}

			monitor.setProgress(i);
		}

		if (monitor.isCancelled()) {
			for (Program program : programs) {
				AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
				aam.cancelQueuedTasks();
			}
		}
	}

	private boolean initializeAnalysisOptions(Program program, AnalysisOptions analysisOptions,
			AutoAnalysisManager mgr) {

		if (analysisOptions == null) {
			mgr.initializeOptions();
			return true;
		}

		ProgramID programID = new ProgramID(program);
		if (!programID.equals(analysisOptions.getProgramID())) {
			// programs are not of the same language/compiler
			return false;
		}

		mgr.initializeOptions(analysisOptions.getAnalysisOptionsPropertyList());
		return true;
	}

	private boolean setOptions(final Program program, AutoAnalysisManager mgr) {
		AtomicBoolean analyze = new AtomicBoolean();
		int id = program.startTransaction("analysis");
		try {
			Swing.runNow(() -> {
				AnalysisOptionsDialog dialog =
					new AnalysisOptionsDialog(getValidProgramsByArchitecture());
				tool.showDialog(dialog);
				boolean shouldAnalyze = dialog.wasAnalyzeButtonSelected();
				analyze.set(shouldAnalyze);
			});
		}
		finally {
			program.endTransaction(id, true);
		}

		if (!analyze.get()) {
			return false;
		}

		return true;
	}

	/**
	 * Returns a list of all programs that should be analyzed. 
	 * <p>
	 * This will always include the currently selected program, as well as any 
	 * other programs that have a similar architecture. Those programs with 
	 * different architectures will be filtered out.
	 * 
	 * @return the list of programs to analyze
	 */
	private List<Program> getValidProgramsByArchitecture() {
		List<Program> validList = new ArrayList<>(programs);

		ProgramID protoTypeProgramID = new ProgramID(prototypeProgram);

		for (Program program : programs) {
			ProgramID programID = new ProgramID(program);
			if (!protoTypeProgramID.equals(programID)) {
				validList.remove(program);
			}
		}

		return validList;
	}

	/**
	 * Verifies that all programs to be analyzed have similar architectures (if
	 * not, they can't be analyzed in a single batch, as their analyzer options
	 * do not match). 
	 * <p>
	 * If any architectures do not match, the user will be notified via
	 * a popup dialog.
	 * 
	 * @return the list of programs that can be analyzed, or null if the operation
	 * was cancelled by the user
	 * @throws CancelledException if the user cancelled the operation
	 */
	private List<Program> checkForInvalidProgramsByArchitecture() throws CancelledException {

		List<Program> validList = getValidProgramsByArchitecture();

		if (validList.size() != programs.size()) {
			List<Program> invalidList = new ArrayList<>(programs);
			invalidList.removeAll(validList);

			if (!showNonMatchingArchitecturesWarning(validList, invalidList)) {
				throw new CancelledException();
			}
		}

		return validList;
	}

	private void appendTableHeader(StringBuilder buffy) {
		buffy.append("<TR>");
		buffy.append("<TH ALIGN=\"left\">");
		buffy.append("<U>Name</U>");
		buffy.append("</TH>");
		buffy.append("<TH ALIGN=\"left\">");
		buffy.append("<U>Language ID</U>");
		buffy.append("</TH>");
		buffy.append("<TH ALIGN=\"left\">");
		buffy.append("<U>Compiler ID</U>");
		buffy.append("</TH>");
		buffy.append("</TR>");
	}

	private boolean showNonMatchingArchitecturesWarning(List<Program> validList,
			List<Program> invalidList) {

		StringBuilder buffy = new StringBuilder();
		buffy.append("<html><BR>");
		buffy.append(
			"Found open programs with architectures differing from the current program.<BR><BR><BR>");
		buffy.append("These programs <B>will</B> be analyzed: <BR><BR>");

		buffy.append("<TABLE BORDER=\"0\" CELLPADDING=\"5\">");

		appendTableHeader(buffy);

		String specialFontOpen = "<B><font color=\"green\">";
		String specialFontClose = "</font></B>";

		for (Program program : validList) {
			boolean isCurrentProgram = program == prototypeProgram;
			if (!isCurrentProgram) { // mark only the current program with special font
				specialFontOpen = "";
				specialFontClose = "";
			}

			buffy.append("<TR>");
			buffy.append("<TD>");
			buffy.append(specialFontOpen);
			buffy.append(HTMLUtilities.escapeHTML(program.getName()));
			buffy.append(specialFontClose);
			buffy.append("</TD>");
			buffy.append("<TD>");
			buffy.append(specialFontOpen);
			buffy.append(program.getLanguageID());
			buffy.append(specialFontClose);
			buffy.append("</TD>");
			buffy.append("<TD>");
			buffy.append(specialFontOpen);
			buffy.append(program.getCompilerSpec().getCompilerSpecID());
			buffy.append(specialFontClose);
			buffy.append("</TD>");
			buffy.append("</TR>");
		}

		buffy.append("<TR>");
		buffy.append("<TD COLSPAN=\"3\">");
		buffy.append("<BR><BR>These programs will <B>not</B> be analyzed: <BR><BR>");
		buffy.append("</TD>");
		buffy.append("</TR>");

		appendTableHeader(buffy);

		for (Program program : invalidList) {
			buffy.append("<TR>");
			buffy.append("<TD>");
			buffy.append(HTMLUtilities.escapeHTML(program.getName()));
			buffy.append("</TD>");
			buffy.append("<TD>");
			buffy.append(program.getLanguageID());
			buffy.append("</TD>");
			buffy.append("<TD>");
			buffy.append(program.getCompilerSpec().getCompilerSpecID());
			buffy.append("</TD>");
			buffy.append("</TR>");
		}

		buffy.append("</TABLE>");

		return Swing.runNow(() -> {
			ScrollingOptionDialog dialog = new ScrollingOptionDialog(buffy.toString());
			return dialog.shouldContinue();
		});
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DefaultAnalyzeProgramStrategy extends AnalyzeProgramStrategy {
		@Override
		protected void analyzeProgram(Program program, AutoAnalysisManager manager,
				TaskMonitor monitor) {

			MyAnalysisBackgroundCommand cmd = new MyAnalysisBackgroundCommand(manager);
			tool.executeBackgroundCommand(cmd, program);

			try {
				cmd.waitUntilFinished();
			}
			catch (InterruptedException e) {
				// assume all is bad and move on
				monitor.cancel();
			}
		}
	}

	private class MyAnalysisBackgroundCommand extends AnalysisBackgroundCommand {

		private CountDownLatch finishedLatch = new CountDownLatch(1);
		private AutoAnalysisManager manager;

		public MyAnalysisBackgroundCommand(AutoAnalysisManager mgr) {
			super(mgr, true);
			manager = mgr;
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			monitor.addCancelledListener(bottomUpCancelledListener);

			// note: this call has to be here, so our listener on the monitor is in place
			manager.reAnalyzeAll(null);

			boolean result = super.applyTo(obj, monitor);
			monitor.removeCancelledListener(bottomUpCancelledListener);
			finishedLatch.countDown();
			return result;
		}

		void waitUntilFinished() throws InterruptedException {
			finishedLatch.await();
		}
	}

	private class BottomUpCancelledListener implements CancelledListener {

		private TaskMonitor outerMonitor;

		BottomUpCancelledListener(TaskMonitor outerMonitor) {
			this.outerMonitor = outerMonitor;
		}

		@Override
		public void cancelled() {
			outerMonitor.cancel();
		}
	}

	private class TopDownCancelledListener implements CancelledListener {
		@Override
		public void cancelled() {
			tool.cancelCurrentTask();
		}
	}

	private class AnalysisOptions {
		private Options options;
		private ProgramID programID;

		AnalysisOptions(Program program) {
			options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			programID = new ProgramID(program);
		}

		ProgramID getProgramID() {
			return programID;
		}

		Options getAnalysisOptionsPropertyList() {
			return options;
		}
	}

	private class ProgramID {
		private LanguageID languageID;
		private CompilerSpecID compilerSpecID;

		ProgramID(Program program) {
			languageID = program.getLanguageID();
			compilerSpecID = program.getCompilerSpec().getCompilerSpecID();
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getOuterType().hashCode();
			result = prime * result + ((compilerSpecID == null) ? 0 : compilerSpecID.hashCode());
			result = prime * result + ((languageID == null) ? 0 : languageID.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}

			ProgramID other = (ProgramID) obj;
			if (!getOuterType().equals(other.getOuterType())) {
				return false;
			}

			if (compilerSpecID == null) {
				if (other.compilerSpecID != null) {
					return false;
				}
			}
			else if (!compilerSpecID.equals(other.compilerSpecID)) {
				return false;
			}
			if (languageID == null) {
				if (other.languageID != null) {
					return false;
				}
			}
			else if (!languageID.equals(other.languageID)) {
				return false;
			}
			return true;
		}

		private AnalyzeAllOpenProgramsTask getOuterType() {
			return AnalyzeAllOpenProgramsTask.this;
		}
	}

	private class ScrollingOptionDialog extends OptionDialog {

		public ScrollingOptionDialog(String message) {
			super("Found Differing Architectures", message, "Continue",
				OptionDialog.WARNING_MESSAGE, null);
		}

		boolean shouldContinue() {
			return Swing.runNow(() -> {
				show(null);
				return getResult() == OptionDialog.OPTION_ONE;
			});
		}

		@Override
		protected JPanel createTextPanel(String message) {
			if (message != null && message.toLowerCase().startsWith("<html>")) {
				JEditorPane editorPane = new JEditorPane();
				editorPane.setEditorKit(new HTMLEditorKit());
				editorPane.setName(MESSAGE_COMPONENT_NAME);
				editorPane.setText(message);

				editorPane.setBackground(new GLabel().getBackground());

				JPanel panel = new JPanel(new BorderLayout());
				panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
				JScrollPane scrollPane = new JScrollPane(editorPane);
				scrollPane.setBorder(BorderFactory.createEmptyBorder());
				panel.add(scrollPane);
				return panel;
			}
			return super.createTextPanel(message);
		}
	}

}
