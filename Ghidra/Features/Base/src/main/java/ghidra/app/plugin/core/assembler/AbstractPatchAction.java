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
package ghidra.app.plugin.core.assembler;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.listingpanel.ListingModelAdapter;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;

/**
 * An abstract action for patching
 *
 * <p>
 * This handles most of the field placement, but relies on quite a few callbacks.
 */
public abstract class AbstractPatchAction extends DockingAction {
	protected static final String MENU_GROUP = "Disassembly";

	protected final PluginTool tool;

	private FieldPanelOverLayoutManager fieldLayoutManager;
	private CodeViewerProvider codeViewerProvider;
	private FieldPanel fieldPanel;
	private ListingPanel listingPanel;

	private Program program;
	private Address address;
	private CodeUnit codeUnit;

	private final KeyListener listenerForKeys = new KeyAdapter() {
		@Override
		public void keyPressed(KeyEvent e) {
			if (e.isConsumed()) {
				return;
			}
			switch (e.getKeyCode()) {
				case KeyEvent.VK_ESCAPE:
					cancel();
					e.consume();
					break;
				case KeyEvent.VK_ENTER:
					accept();
					e.consume();
					break;
			}
		}
	};

	private final FocusListener listenerForFocusLost = new FocusAdapter() {
		@Override
		public void focusLost(FocusEvent e) {
			cancel();
		}
	};

	/**
	 * Create a new action owned by the given plugin, having the given name
	 *
	 * @param owner the plugin owning the action
	 * @param name the name of the action
	 */
	public AbstractPatchAction(Plugin owner, String name) {
		super(name, owner.getName());
		tool = owner.getTool();
	}

	/**
	 * Initialize the action, post construction
	 */
	protected void init() {
		addInputFocusListener(listenerForFocusLost);
		addInputKeyListener(listenerForKeys);
	}

	/**
	 * Add the given focus listener to your input field(s)
	 *
	 * <p>
	 * The action uses this to know when those fields have lost focus, so it can cancel the action.
	 *
	 * @param listener the listener
	 */
	protected abstract void addInputFocusListener(FocusListener listener);

	/**
	 * Add the given key listener to your input field(s)
	 *
	 * <p>
	 * The listener handles Escape and Enter, canceling or accepting the input, respectively.
	 *
	 * @param listener the listener
	 */
	protected abstract void addInputKeyListener(KeyListener listener);

	/**
	 * If needed, add your layout listeners to this action's layout manager
	 *
	 * <p>
	 * If there are additional components that need to move, e.g., when the panel is scrolled, then
	 * you need a layout listener. If this is overridden, then
	 * {@link #removeLayoutListeners(FieldPanelOverLayoutManager)} must also be overridden.
	 *
	 * @param fieldLayoutManager the layout manager
	 */
	protected void addLayoutListeners(FieldPanelOverLayoutManager fieldLayoutManager) {
		// Extension point
	}

	/**
	 * Remove your layout listeners from this action's layout manager
	 *
	 * @see #addLayoutListeners(FieldPanelOverLayoutManager)
	 */
	protected void removeLayoutListeners(FieldPanelOverLayoutManager fieldLayoutManager) {
		// Extension point
	}

	/**
	 * Set your input field(s) font to the given one
	 *
	 * <p>
	 * This ensures your field's font matches the listing over which it is placed.
	 *
	 * @param font the listing's base font
	 */
	protected abstract void setInputFont(Font font);

	/**
	 * Get the program on which this action was invoked
	 *
	 * @return the current program
	 */
	protected Program getProgram() {
		return program;
	}

	/**
	 * Get the code unit on which this action was invoked
	 *
	 * @return the current code unit
	 */
	protected CodeUnit getCodeUnit() {
		return codeUnit;
	}

	/**
	 * Get the address at which this action was invoked
	 *
	 * @return the current address
	 */
	protected Address getAddress() {
		return address;
	}

	@Override
	public void dispose() {
		super.dispose();
		if (fieldLayoutManager != null) {
			fieldPanel.setLayout(null);
			fieldLayoutManager.unregister();
			removeLayoutListeners(fieldLayoutManager);
		}
	}

	private void prepareLayout(ListingActionContext context) {
		ComponentProvider contextProvider = context.getComponentProvider();
		if (codeViewerProvider == contextProvider) {
			return;
		}

		if (codeViewerProvider != null) {
			fieldPanel.setLayout(null);
			fieldLayoutManager.unregister();
			removeLayoutListeners(fieldLayoutManager);
		}

		codeViewerProvider = (CodeViewerProvider) contextProvider;
		listingPanel = codeViewerProvider.getListingPanel();
		fieldPanel = listingPanel.getFieldPanel();

		fieldLayoutManager = new FieldPanelOverLayoutManager(fieldPanel);
		addLayoutListeners(fieldLayoutManager);
		fieldPanel.setLayout(fieldLayoutManager);
	}

	/**
	 * Invoked when the user presses Enter
	 *
	 * <p>
	 * This should validate the user's input and complete the action. If the action is completed
	 * successfully, then call {@link #hide()}. Note that the Enter key can be ignored by doing
	 * nothing, since the input field(s) will remain visible. In that case, you must provide another
	 * mechanism for completing the action.
	 */
	public abstract void accept();

	/**
	 * Hide the input field(s)
	 *
	 * <p>
	 * This removes any components added to the listing's field panel, usually via
	 * {@link #showInputs(FieldPanel)}, and returns focus to the listing. If other components were
	 * added elsewhere, you must override this and hide them, too.
	 */
	protected void hide() {
		fieldPanel.removeAll();
		fieldLayoutManager.layoutContainer(fieldPanel);
		fieldPanel.requestFocusInWindow();
	}

	/**
	 * Cancel the current patch action
	 *
	 * <p>
	 * This hides the input field(s) without completing the action.
	 */
	public void cancel() {
		hide();
	}

	/**
	 * Locate a listing field by name and address
	 *
	 * <p>
	 * Generally, this is used in {@link #showInputs(FieldPanel)} to find constraints suitable for
	 * use in {@link Container#add(Component, Object)} on the passed {@code fieldPanel}. Likely, the
	 * address should be obtained from {@link #getAddress()}.
	 *
	 * @param address the address for the line (row) in the listing
	 * @param fieldName the column name for the field in the listing
	 * @return if found, the field location, or null
	 */
	protected FieldLocation findFieldLocation(Address address, String fieldName) {
		Layout layout = listingPanel.getLayout(address);
		ListingModelAdapter adapter = (ListingModelAdapter) fieldPanel.getLayoutModel();
		BigInteger index = adapter.getAddressIndexMap().getIndex(address);
		int count = layout.getNumFields();
		for (int i = 0; i < count; i++) {
			ListingField field = (ListingField) layout.getField(i);
			if (field.getFieldFactory().getFieldName().equals(fieldName)) {
				return new FieldLocation(index, i);
			}
		}
		return null;
	}

	/**
	 * Check if the action is applicable to the given code unit
	 *
	 * @param unit the code unit at the user's cursor
	 * @return true if applicable, false if not
	 */
	protected abstract boolean isApplicableToUnit(CodeUnit unit);

	@Override
	public boolean isAddToPopup(ActionContext context) {
		CodeUnit cu = getCodeUnit(context);
		if (cu == null || !isApplicableToUnit(cu)) {
			return false;
		}

		ListingActionContext lac = (ListingActionContext) context;

		ComponentProvider provider = lac.getComponentProvider();
		if (!(provider instanceof CodeViewerProvider)) {
			return false;
		}

		CodeViewerProvider codeViewer = (CodeViewerProvider) provider;
		if (codeViewer.isReadOnly()) {
			return false;
		}

		Program program = lac.getProgram();
		if (program == null) {
			return false;
		}

		Address address = lac.getAddress();
		if (address == null) {
			return false;
		}
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null || !block.isInitialized()) {
			return false;
		}
		return true;
	}

	/**
	 * Perform preparation and save any information needed later in {@link #accept()}.
	 */
	protected void prepare() {
	}

	/**
	 * Put the input fields in their place, show them, and place focus appropriately
	 *
	 * <p>
	 * Use {{@link #findFieldLocation(Address, String)} to locate fields in the listing and place
	 * your inputs over them.
	 *
	 * @param fieldPanel the currently-focused listing field panel
	 * @return false if inputs could not be placed and shown
	 */
	protected abstract boolean showInputs(FieldPanel fieldPanel);

	/**
	 * Pre-fill the input fields and place the caret appropriately (usually at the end)
	 */
	protected abstract void fillInputs();

	protected CodeUnit getCodeUnit(ActionContext context) {
		if (!(context instanceof ListingActionContext)) {
			return null;
		}

		ListingActionContext lac = (ListingActionContext) context;
		ComponentProvider provider = lac.getComponentProvider();
		if (!(provider instanceof CodeViewerProvider)) {
			return null;
		}

		CodeViewerProvider codeViewProvider = (CodeViewerProvider) provider;
		if (codeViewProvider.isReadOnly()) {
			return null;
		}
		return lac.getCodeUnit();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		codeUnit = getCodeUnit(context);
		if (codeUnit == null || !isApplicableToUnit(codeUnit)) {
			return;
		}

		ListingActionContext lac = (ListingActionContext) context;
		prepareLayout(lac);

		ProgramLocation cur = lac.getLocation();
		program = cur.getProgram();
		address = cur.getAddress();
		if (address == null) {
			return;
		}
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null || !block.isInitialized()) {
			return;
		}

		prepare();

		ToolOptions displayOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		Font font = displayOptions.getFont(GhidraOptions.OPTION_BASE_FONT, null);
		if (font != null) {
			setInputFont(font);
		}

		fieldPanel.removeAll();
		if (!showInputs(fieldPanel)) {
			return;
		}
		fillInputs();

		fieldLayoutManager.layoutContainer(fieldPanel);
	}
}
