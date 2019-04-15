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
package ghidra.app.plugin.core.diff;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collections;

import javax.swing.*;

import docking.WindowPosition;
import docking.widgets.VariableHeightPanel;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import ghidra.app.plugin.core.diff.DiffApplySettingsOptionManager.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.util.ProgramMergeFilter;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * The DiffSettingsDialog is used to change the types of differences currently 
 * highlighted. It also allows the user to change the types of differences being 
 * applied and whether labels and/or comments are being merged or replaced.
 */
public class DiffApplySettingsProvider extends ComponentProviderAdapter {

	public static final String APPLY_FILTER_CHANGED_ACTION = "Apply Filter Changed";
	public static final ImageIcon ICON = ResourceManager.loadImage("images/settings16.gif");
	public static final String TITLE = "Diff Apply Settings";

	private ProgramDiffPlugin plugin;

	private ArrayList<Choice> choices;
	private Choice programContextCB;
	private Choice bytesCB;
	private Choice codeUnitsCB;
	private Choice refsCB;
	private SymbolsChoice symbolsCB;
	private Choice plateCommentsCB;
	private Choice preCommentsCB;
	private Choice eolCommentsCB;
	private Choice repeatableCommentsCB;
	private Choice postCommentsCB;
	private Choice bookmarksCB;
	private Choice propertiesCB;
	private Choice functionsCB;
	private Choice functionTagsCB;

	private int applyProgramContext;
	private int applyBytes;
	private int applyCodeUnits;
	private int applyReferences;
	private int applyPlateComments;
	private int applyPreComments;
	private int applyEolComments;
	private int applyRepeatableComments;
	private int applyPostComments;
	private int applySymbols;
	private int applyBookmarks;
	private int applyProperties;
	private int applyFunctions;
	private int applyFunctionTags;
	private int replacePrimary;

	private ProgramMergeFilter applyFilter;
	private boolean adjustingApplyFilter = false;
	private JComponent applyPanel;
	private ArrayList<ActionListener> listenerList = new ArrayList<>();
	private boolean pgmContextEnabled = true;

	public DiffApplySettingsProvider(ProgramDiffPlugin plugin) {
		super(plugin.getTool(), TITLE, plugin.getName());
		this.plugin = plugin;
		setIcon(ICON);
		setWindowMenuGroup("Diff");
		setDefaultWindowPosition(WindowPosition.BOTTOM);

		// transient so that is only there while the Diff is available
		setTransient();

		setHelpLocation(new HelpLocation("Diff", "Diff_Apply_Settings"));
		applyPanel = createApplyFilterPanel();
		applyPanel.setName("Diff Apply Settings Panel");
	}

	public void configure(ProgramMergeFilter apply) {
		setApplyFilter(apply);
	}

	public void addActions() {
		plugin.getTool().addLocalAction(this,
			new SaveApplySettingsAction(this, plugin.applySettingsMgr));
		plugin.getTool().addLocalAction(this, new DiffIgnoreAllAction(this));
		plugin.getTool().addLocalAction(this, new DiffReplaceAllAction(this));
		plugin.getTool().addLocalAction(this, new DiffMergeAllAction(this));
	}

	/**
	 *  Create a panel for the user choices to indicate the filter settings.
	 */
	private void createChoices() {
		choices = new ArrayList<>();
		programContextCB = new Choice("Program Context", false);
		programContextCB.addActionListener(e -> {
			applyProgramContext = programContextCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.PROGRAM_CONTEXT, applyProgramContext);
			applyFilterChanged();
		});
		choices.add(programContextCB);

		bytesCB = new Choice("Bytes", false);
		bytesCB.addActionListener(e -> {
			applyBytes = bytesCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.BYTES, applyBytes);
			applyFilterChanged();
		});
		choices.add(bytesCB);

		codeUnitsCB = new Choice("Code Units", false);
		codeUnitsCB.addActionListener(e -> {
			applyCodeUnits = codeUnitsCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.CODE_UNITS | ProgramMergeFilter.EQUATES,
				applyCodeUnits);
			applyFilterChanged();
		});
		choices.add(codeUnitsCB);

		refsCB = new Choice("References", false);
		refsCB.addActionListener(e -> {
			applyReferences = refsCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.REFERENCES, applyReferences);
			applyFilterChanged();
		});
		choices.add(refsCB);

		plateCommentsCB = new Choice("Plate Comments", true);
		plateCommentsCB.addActionListener(e -> {
			applyPlateComments = plateCommentsCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.PLATE_COMMENTS, applyPlateComments);
			applyFilterChanged();
		});
		choices.add(plateCommentsCB);

		preCommentsCB = new Choice("Pre Comments", true);
		preCommentsCB.addActionListener(e -> {
			applyPreComments = preCommentsCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.PRE_COMMENTS, applyPreComments);
			applyFilterChanged();
		});
		choices.add(preCommentsCB);

		eolCommentsCB = new Choice("Eol Comments", true);
		eolCommentsCB.addActionListener(e -> {
			applyEolComments = eolCommentsCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.EOL_COMMENTS, applyEolComments);
			applyFilterChanged();
		});
		choices.add(eolCommentsCB);

		repeatableCommentsCB = new Choice("Repeatable Comments", true);
		repeatableCommentsCB.addActionListener(e -> {
			applyRepeatableComments = repeatableCommentsCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.REPEATABLE_COMMENTS, applyRepeatableComments);
			applyFilterChanged();
		});
		choices.add(repeatableCommentsCB);

		postCommentsCB = new Choice("Post Comments", true);
		postCommentsCB.addActionListener(e -> {
			applyPostComments = postCommentsCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.POST_COMMENTS, applyPostComments);
			applyFilterChanged();
		});
		choices.add(postCommentsCB);

		symbolsCB = new SymbolsChoice();
		symbolsCB.addActionListener(e -> {
			SYMBOL_MERGE_CHOICE symbols =
				SYMBOL_MERGE_CHOICE.values()[symbolsCB.getSelectedIndex()];
			MERGE_CHOICE merge =
				plugin.applySettingsMgr.convertSymbolMergeChoiceToMergeChoice(symbols);
			REPLACE_CHOICE primary =
				plugin.applySettingsMgr.convertSymbolMergeChoiceToReplaceChoiceForPrimay(symbols);
			applySymbols = merge.ordinal();
			replacePrimary = primary.ordinal();
			applyFilter.setFilter(ProgramMergeFilter.SYMBOLS, applySymbols);
			applyFilter.setFilter(ProgramMergeFilter.PRIMARY_SYMBOL, replacePrimary);
			applyFilterChanged();
		});
		choices.add(symbolsCB);

		bookmarksCB = new Choice("Bookmarks", false);
		bookmarksCB.addActionListener(e -> {
			applyBookmarks = bookmarksCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.BOOKMARKS, applyBookmarks);
			applyFilterChanged();
		});
		choices.add(bookmarksCB);

		propertiesCB = new Choice("Properties", false);
		propertiesCB.addActionListener(e -> {
			applyProperties = propertiesCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.PROPERTIES, applyProperties);
			applyFilterChanged();
		});
		choices.add(propertiesCB);

		functionsCB = new Choice("Functions", false);
		functionsCB.addActionListener(e -> {
			applyFunctions = functionsCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.FUNCTIONS, applyFunctions);
			applyFilterChanged();
		});
		choices.add(functionsCB);

		functionTagsCB = new Choice("Function Tags", true);
		functionTagsCB.addActionListener(e -> {
			applyFunctionTags = functionTagsCB.getSelectedIndex();
			applyFilter.setFilter(ProgramMergeFilter.FUNCTION_TAGS, applyFunctionTags);
			applyFilterChanged();
		});
		choices.add(functionTagsCB);

		int maxLabelWidth = 0;
		int maxComboWidth = 0;
		for (Choice choice : choices) {
			maxLabelWidth = Math.max(maxLabelWidth, choice.label.getPreferredSize().width);
			maxComboWidth = Math.max(maxComboWidth, choice.applyCB.getPreferredSize().width);
		}
		for (Choice choice : choices) {
			int height = choice.label.getPreferredSize().height;
			choice.label.setPreferredSize(new Dimension(maxLabelWidth, height));
			height = choice.applyCB.getPreferredSize().height;
			choice.applyCB.setPreferredSize(new Dimension(maxComboWidth, height));
		}
		Collections.sort(choices);
	}

	/**
	 *  Create a panel for the checkboxes to indicate the filter settings.
	 */
	private JComponent createApplyFilterPanel() {
		createChoices();
		VariableHeightPanel panel = new VariableHeightPanel(false, 10, 3);

		panel.setToolTipText("<HTML>" +
			"For each difference type, select whether to ignore, replace, or merge." +
			"<BR>&nbsp&nbsp<B>Ignore</B> - don't apply this type of difference." +
			"<BR>&nbsp&nbsp<B>Replace</B> - replace the difference type with the one from program 2." +
			"<BR>&nbsp&nbsp<B>Merge</B> - merge the difference type from program 2 with what's there." +
			"</HTML>");
		for (Choice choice : choices) {
			panel.add(choice);
		}

		return new JScrollPane(panel);
	}

	private void adjustApplyFilter() {
		try {
			adjustingApplyFilter = true;
			programContextCB.setSelectedIndex(applyProgramContext);
			bytesCB.setSelectedIndex(applyBytes);
			codeUnitsCB.setSelectedIndex(applyCodeUnits);
			refsCB.setSelectedIndex(applyReferences);
			plateCommentsCB.setSelectedIndex(applyPlateComments);
			preCommentsCB.setSelectedIndex(applyPreComments);
			eolCommentsCB.setSelectedIndex(applyEolComments);
			repeatableCommentsCB.setSelectedIndex(applyRepeatableComments);
			postCommentsCB.setSelectedIndex(applyPostComments);
			int symbolsIndex =
				plugin.applySettingsMgr.convertFiltersToSymbolIndex(applySymbols, replacePrimary);
			symbolsCB.setSelectedIndex(symbolsIndex);
			bookmarksCB.setSelectedIndex(applyBookmarks);
			propertiesCB.setSelectedIndex(applyProperties);
			functionsCB.setSelectedIndex(applyFunctions);
			functionTagsCB.setSelectedIndex(applyFunctionTags);
		}
		finally {
			adjustingApplyFilter = false;
			applyFilterChanged();
		}
	}

	void setPgmContextEnabled(boolean enable) {
		pgmContextEnabled = enable;
		if (!pgmContextEnabled) {
			applyProgramContext = 0;
			programContextCB.setSelectedIndex(applyProgramContext);
		}
	}

	/**
	 * Get a copy of the merge filter for applying differences.
	 * @return the current merge Filter settings.
	 */
	ProgramMergeFilter getApplyFilter() {
		return new ProgramMergeFilter(applyFilter);
	}

	/**
	 * Sets the diff tool merge filter settings for applying differences.
	 * @param filter the new apply Filter settings.
	 */
	void setApplyFilter(ProgramMergeFilter filter) {
		applyFilter = new ProgramMergeFilter(filter);
		applyProgramContext = applyFilter.getFilter(ProgramMergeFilter.PROGRAM_CONTEXT);
		applyBytes = applyFilter.getFilter(ProgramMergeFilter.BYTES);
		applyCodeUnits = Math.max(applyFilter.getFilter(ProgramMergeFilter.INSTRUCTIONS),
			applyFilter.getFilter(ProgramMergeFilter.DATA));
		applyFilter.setFilter(ProgramMergeFilter.CODE_UNITS, applyCodeUnits);
		applyReferences = applyFilter.getFilter(ProgramMergeFilter.REFERENCES);
		applyPlateComments = applyFilter.getFilter(ProgramMergeFilter.PLATE_COMMENTS);
		applyPreComments = applyFilter.getFilter(ProgramMergeFilter.PRE_COMMENTS);
		applyEolComments = applyFilter.getFilter(ProgramMergeFilter.EOL_COMMENTS);
		applyRepeatableComments = applyFilter.getFilter(ProgramMergeFilter.REPEATABLE_COMMENTS);
		applyPostComments = applyFilter.getFilter(ProgramMergeFilter.POST_COMMENTS);
		applySymbols = applyFilter.getFilter(ProgramMergeFilter.SYMBOLS);
		applyBookmarks = applyFilter.getFilter(ProgramMergeFilter.BOOKMARKS);
		applyProperties = applyFilter.getFilter(ProgramMergeFilter.PROPERTIES);
		applyFunctions = applyFilter.getFilter(ProgramMergeFilter.FUNCTIONS);
		applyFunctionTags = applyFilter.getFilter(ProgramMergeFilter.FUNCTION_TAGS);
		replacePrimary = applyFilter.getFilter(ProgramMergeFilter.PRIMARY_SYMBOL);

		adjustApplyFilter();
	}

	public void addActionListener(ActionListener listener) {
		listenerList.add(listener);
	}

	public void removeActionListener(ActionListener listener) {
		listenerList.remove(listener);
	}

	/**
	 * Return true if at least one of the checkboxes for the filter
	 * has been selected.
	 */
	boolean hasApplySelection() {
		return ((applyProgramContext | applyBytes | applyCodeUnits | applyReferences |
			applyPlateComments | applyPreComments | applyEolComments | applyRepeatableComments |
			applyPostComments | applySymbols | applyBookmarks | applyProperties | applyFunctions |
			applyFunctionTags) != 0);
	}

	protected void applyFilterChanged() {
		if (adjustingApplyFilter) {
			return;
		}
		for (int i = 0; i < listenerList.size(); i++) {
			ActionListener listener = listenerList.get(i);
			listener.actionPerformed(new ActionEvent(this, 0, APPLY_FILTER_CHANGED_ACTION));
		}
	}

	@Override
	public void closeComponent() {
		// overridden to not remove this transient provider
		plugin.getTool().showComponentProvider(this, false);
	}

	@Override
	public JComponent getComponent() {
		return applyPanel;
	}

	/**
	 * Gets the plugin associated with this provider.
	 */
	Plugin getPlugin() {
		return plugin;
	}

	class Choice extends JPanel implements Comparable<Choice> {
		private final static long serialVersionUID = 1L;
		String type;
		boolean allowMerge;
		JLabel label;
		JComboBox<Enum<?>> applyCB;

		public Choice(String type, boolean allowMerge) {
			setLayout(new BorderLayout());
			this.type = type;
			this.allowMerge = allowMerge;
			init();
		}

		protected void init() {
			applyCB =
				new GComboBox<>(allowMerge ? DiffApplySettingsOptionManager.MERGE_CHOICE.values()
						: DiffApplySettingsOptionManager.REPLACE_CHOICE.values());
			applyCB.setName(type + " Diff Apply CB");
			String typeName = type;
			if (typeName.endsWith(" Comments")) {
				typeName = "Comments, " + typeName.substring(0, typeName.length() - 9);
			}
			label = new GDLabel(" " + typeName + " ");
			label.setHorizontalAlignment(SwingConstants.RIGHT);
			add(applyCB, BorderLayout.EAST);
			add(label, BorderLayout.CENTER);
		}

		void setSelectedIndex(int index) {
			applyCB.setSelectedIndex(index);
		}

		int getSelectedIndex() {
			return applyCB.getSelectedIndex();
		}

		public void addActionListener(ActionListener listener) {
			applyCB.addActionListener(listener);
		}

		public void removeActionListener(ActionListener listener) {
			applyCB.removeActionListener(listener);
		}

		void setLabelSize(Dimension preferredSize) {
			label.setPreferredSize(preferredSize);
		}

		void setComboSize(Dimension preferredSize) {
			applyCB.setPreferredSize(preferredSize);
		}

		@Override
		public int compareTo(Choice o) {
			return label.toString().compareTo(o.label.toString());
		}

	}

	class SymbolsChoice extends Choice {
		private final static long serialVersionUID = 1L;

		public SymbolsChoice() {
			super("Labels", true);
		}

		@Override
		protected void init() {
			applyCB = new GComboBox<>(DiffApplySettingsOptionManager.SYMBOL_MERGE_CHOICE.values());
			applyCB.setName(type + " Diff Apply CB");
			label = new GDLabel(" " + type + " ");
			label.setHorizontalAlignment(SwingConstants.RIGHT);
			add(applyCB, BorderLayout.EAST);
			add(label, BorderLayout.CENTER);
		}
	}
}
