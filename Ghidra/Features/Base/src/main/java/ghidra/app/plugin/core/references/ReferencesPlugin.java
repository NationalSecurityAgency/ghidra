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
package ghidra.app.plugin.core.references;

import java.awt.Component;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.*;

import javax.swing.JComponent;

import org.jdom.Element;

import docking.ComponentProvider;
import docking.action.*;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.refs.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.SymbolInspector;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.framework.cmd.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "View/Edit references",
	description = "Provides a dockable window for adding, removing, and editing references from an instruction or data location.",
	servicesRequired = { GoToService.class, ProgramManager.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class, ProgramClosedPluginEvent.class, ProgramLocationPluginEvent.class }
)
//@formatter:on
public class ReferencesPlugin extends Plugin {

	static final String REFS_GROUP = "references";
	static final String SHOW_REFS_GROUP = "ShowReferences";
	static final String SUBMENU_NAME = "References";

	private Program currentProgram;
	private ProgramLocation currentLocation;

	private GoToService goToService;
	private ProgramManager programMgr;

	private BrowserCodeUnitFormat cuFormat;
	private SymbolInspector symbolInspector;

	private DockingAction showAction;
	private DeleteReferencesAction deleteAction;
	private CreateDefaultReferenceAction createAction;
	private DockingAction addAction;

	private List<EditReferencesProvider> editRefProviders = new ArrayList<>();
	private EditReferenceDialog editRefDialog;

	private ExternalReferencesProvider externalReferencesProvider;
	private boolean defaultFollowOnLocation = false;
	private boolean defaultGotoReferenceLocation;

	public ReferencesPlugin(PluginTool tool) {
		super(tool);

		setupActions();

		externalReferencesProvider = new ExternalReferencesProvider(this);
	}

	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
		programMgr = tool.getService(ProgramManager.class);
		cuFormat = new BrowserCodeUnitFormat(tool);
		symbolInspector = new SymbolInspector(tool, null);
	}

	@Override
	public void dispose() {
		disposeAllDialogs();
		disposeAllProviders();
		showAction.dispose();
		createAction.dispose();
		deleteAction.dispose();
		addAction.dispose();
		externalReferencesProvider.dispose();
		symbolInspector.dispose();
		super.dispose();
	}

	private void disposeAllProviders() {
		for (EditReferencesProvider provider : editRefProviders) {
			provider.dispose();
		}
		editRefProviders.clear();
	}

	private void disposeProvider(EditReferencesProvider provider) {
		editRefProviders.remove(provider);
		provider.dispose();
	}

	private void cleanupProviders(Program p, boolean closed) {
		boolean keepOne = true;
		Iterator<EditReferencesProvider> iter = editRefProviders.iterator();
		while (iter.hasNext()) {
			EditReferencesProvider provider = iter.next();
			if (p == provider.getCurrentProgram() && (closed || !provider.isLocationLocked())) {
				if (keepOne && !provider.isLocationLocked()) {
					provider.show(null, null);
					keepOne = false;
				}
				else {
					provider.dispose();
					iter.remove();
				}
			}
		}
	}

	private void disposeAllDialogs() {
		if (editRefDialog != null) {
			editRefDialog.dispose();
			editRefDialog = null;
		}
	}

	private void setupActions() {

		tool.setMenuGroup(new String[] { SUBMENU_NAME }, REFS_GROUP);

		showAction = new ListingContextAction("View/Edit References From", getName()) {
			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				return context.getLocation() instanceof CodeUnitLocation;
			}

			@Override
			protected void actionPerformed(ListingActionContext context) {
				editReferenceAtLocation(context.getProgram(), context.getLocation());
			}
		};
		showAction.setPopupMenuData(
			new MenuData(new String[] { SUBMENU_NAME, "Add/Edit..." }, null, SHOW_REFS_GROUP));
		showAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_R, 0));

		showAction.setDescription(
			"View, add, remove, or edit all types of references from a code unit");
		tool.addAction(showAction);

		createAction = new CreateDefaultReferenceAction(this);
		createAction.setPopupMenuData(new MenuData(
			new String[] { SUBMENU_NAME, CreateDefaultReferenceAction.DEFAULT_MENU_ITEM_NAME },
			null, SHOW_REFS_GROUP));
		createAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_R,
			InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK));

		createAction.setDescription("Create default forward reference");
		tool.addAction(createAction);

		addAction = new ListingContextAction("Add Reference From", getName()) {
			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				ProgramLocation loc = context.getLocation();
				return (loc instanceof CodeUnitLocation && context.getCodeUnit() != null);
			}

			@Override
			protected void actionPerformed(ListingActionContext context) {
				ProgramLocation loc = context.getLocation();
				CodeUnit cu = context.getCodeUnit();
				int opIndex = CodeUnit.MNEMONIC;
				int subIndex = -1;
				if (loc instanceof OperandFieldLocation) {
					opIndex = ((OperandFieldLocation) loc).getOperandIndex();
					subIndex = ((OperandFieldLocation) loc).getSubOperandIndex();
				}
				if (cu != null) {
					popupAddReferenceDialog(cu, opIndex, subIndex, null);
				}
			}
		};
		addAction.setPopupMenuData(new MenuData(
			new String[] { SUBMENU_NAME, "Add Reference from..." }, null, SHOW_REFS_GROUP));

		addAction.setEnabled(true);
		tool.addAction(addAction);

		// Deprecated key bindings for CreateDefaultReferenceAction

		tool.addAction(new CreateRefActionWrapper(CreateDefaultReferenceAction.MEMORY_REF_CLASS,
			"Add Default Memory Reference", KeyEvent.VK_M));

		tool.addAction(new CreateRefActionWrapper(CreateDefaultReferenceAction.STACK_REF_CLASS,
			"Set Default Stack Reference", KeyEvent.VK_S));

		tool.addAction(new CreateRefActionWrapper(CreateDefaultReferenceAction.REGISTER_REF_CLASS,
			"Set Default Register Reference", KeyEvent.VK_R));

		deleteAction = new DeleteReferencesAction(this);
		tool.addAction(deleteAction);
	}

	/**
	 * Wrapper class for createRefAction, allowing deprecated key bindings to
	 * set for specific reference class.
	 */
	private class CreateRefActionWrapper extends ListingContextAction {

		final int refClass;

		CreateRefActionWrapper(int refClass, String name, int keyCode) {
			super(name, ReferencesPlugin.this.getName());
			this.refClass = refClass;
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_M, 0));
			setHelpLocation(new HelpLocation("ReferencesPlugin", "Create_Default_Reference"));

		}

		@Override
		protected boolean isEnabledForContext(ListingActionContext context) {
			return createAction.isEnabledForContext(context) &&
				refClass == createAction.getDefaultRefClass();
		}

		@Override
		protected void actionPerformed(ListingActionContext context) {
			createAction.actionPerformed(context);
		}
	}

	/*
	 * @see ghidra.framework.plugintool.Plugin#processEvent(ghidra.framework.plugintool.PluginEvent)
	 */
	@Override
	public void processEvent(PluginEvent event) {
		//		createAction.invalidateContext();
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent evt = (ProgramActivatedPluginEvent) event;
			Program newProg = evt.getActiveProgram();
			if (currentProgram != null) {
				programDeactivated(currentProgram);
			}
			if (newProg != null) {
				programActivated(newProg);
			}
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent evt = (ProgramClosedPluginEvent) event;
			programClosed(evt.getProgram());
		}
		else if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocationPluginEvent evt = (ProgramLocationPluginEvent) event;
			locationChanged(evt.getLocation());
		}

	}

	private void locationChanged(ProgramLocation loc) {
		if (loc == null) {
			return;
		}
		currentLocation = loc;
		for (EditReferencesProvider referencesProvider : editRefProviders) {
			if (tool.isVisible(referencesProvider) && !referencesProvider.isLocationLocked()) {
				referencesProvider.updateForLocation(currentProgram, loc);
			}
		}
	}

	EditReferenceDialog popupAddReferenceDialog(CodeUnit cu, int opIndex, int subIndex,
			EditReferencesProvider provider) {
		if (editRefDialog == null) {
			editRefDialog = new EditReferenceDialog(this);
		}
		editRefDialog.initDialog(cu, opIndex, subIndex, null);
		tool.showDialog(editRefDialog, provider);
		return editRefDialog;
	}

	EditReferenceDialog popupEditReferenceDialog(CodeUnit cu, Reference ref,
			EditReferencesProvider provider) {
		if (editRefDialog == null) {
			editRefDialog = new EditReferenceDialog(this);
		}
		editRefDialog.initDialog(cu, ref.getOperandIndex(), -1, ref);
		tool.showDialog(editRefDialog, provider);
		return editRefDialog;
	}

	private void programActivated(Program program) {
		currentProgram = program;
		externalReferencesProvider.setProgram(program);
	}

	private void programDeactivated(Program program) {
		currentProgram = null;
		currentLocation = null;
		externalReferencesProvider.setProgram(null);
		if (editRefDialog != null) {
			editRefDialog.close();
		}
		cleanupProviders(program, false);
	}

	private void programClosed(Program program) {
		if (editRefDialog != null) {
			editRefDialog.close();
		}
		cleanupProviders(program, true);
	}

	Program getCurrentProgram() {
		return currentProgram;
	}

	ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	private void editReferenceAtLocation(Program program, ProgramLocation location) {
		EditReferencesProvider openProvider = findOpenProvider(program, location);
		if (openProvider != null) {
			openProvider.show(openProvider.getCurrentProgram(), openProvider.getInitLocation());
		}
		else {
			EditReferencesProvider provider = new EditReferencesProvider(this);
			provider.show(program, location);
			editRefProviders.add(provider);
		}
	}

	private EditReferencesProvider findOpenProvider(Program program, ProgramLocation location) {
		for (EditReferencesProvider provider : editRefProviders) {
			if (isProviderCodeUnitMatch(program, location, provider)) {
				return provider;
			}
		}

		return null;
	}

	private boolean isProviderCodeUnitMatch(Program program, ProgramLocation location,
			EditReferencesProvider provider) {

		ProgramLocation existingProviderLocation = provider.getInitLocation();
		if (existingProviderLocation == null) {
			return false;
		}

		Address address = existingProviderLocation.getAddress();
		if (address == null) {
			return false;
		}

		if (!address.equals(location.getAddress())) {
			return false;
		}

		CodeUnit previousCodeUnit = provider.getCodeUnit();
		if (previousCodeUnit == null) {
			return false;
		}

		CodeUnit newCodeUnit = provider.getCodeUnit(program, location);
		return previousCodeUnit.equals(newCodeUnit);
	}

	void providerClosed(ComponentProvider provider) {
		if (provider instanceof EditReferencesProvider) {
			disposeProvider((EditReferencesProvider) provider);
		}
	}

	void goTo(Program program, Address addr) {
		//			lastGoToAddr = addr;
		goToService.goTo(addr, program);
	}

	void goTo(Program program, ProgramLocation loc) {
		//		lastGoToAddr = loc.getAddress();
		goToService.goTo(loc, program);
	}

	/**
	 * Check a memory address and warn the user if it has an issue.
	 * 
	 * @param c parent component or null
	 * @param mem program memory
	 * @param addr address to check
	 * @param refOffset offset from addr
	 * @return addr to be used or null if user cancels
	 */
	Address checkMemoryAddress(Component c, Program p, Address addr, long refOffset) {
		String warningMsg = "";
		String refOffStr = "";
		if (refOffset != 0) {
			boolean neg = (refOffset < 0);
			refOffStr = (neg ? "-" : "+") + "0x" + Long.toHexString(neg ? -refOffset : refOffset);
		}
		AddressSpace space = addr.getAddressSpace();
		if (space instanceof OverlayAddressSpace) {
			OverlayAddressSpace overlaySpace = (OverlayAddressSpace) space;
			AddressSpace baseSpace =
				p.getAddressFactory().getAddressSpace(overlaySpace.getBaseSpaceID());
			long offset = baseSpace.truncateOffset(addr.getOffset() + refOffset);
			if (!overlaySpace.contains(offset)) {
				Address newAddr = overlaySpace.translateAddress(addr, true);
				warningMsg += "The overlay address " + addr.toString(true) + refOffStr +
					" is not contained within the overlay space '" + overlaySpace.getName() +
					"'\n" + "and will get mapped into the underlying address space (" +
					newAddr.toString(true) + refOffStr + ").\n \n";
				addr = newAddr;
			}
		}
		Address testAddr = addr;
		String wrapStr = "";
		if (refOffset != 0) {
			try {
				testAddr = addr.addNoWrap(refOffset);
			}
			catch (AddressOverflowException e) {
				warningMsg += "The address " + addr.toString(true) + refOffStr +
					" must be wrapped within the address space.\n \n";
				testAddr = addr.addWrap(refOffset);
				wrapStr = "wrapped ";
			}
		}
		if (!p.getMemory().contains(testAddr)) {
			warningMsg += "The equivalent " + wrapStr + "address " + testAddr.toString(true) +
				" is not contained within the Program's defined memory blocks.\n \n";
		}
		if (warningMsg.length() != 0) {
			if (c == null) {
				c = tool.getToolFrame();
			}
			int rc = OptionDialog.showOptionDialog(c, "Set Memory Reference",
				warningMsg + "Do you wish to continue?", "Continue", OptionDialog.WARNING_MESSAGE);
			if (rc != OptionDialog.OPTION_ONE) {
				return null;
			}
		}
		return addr;
	}

	void addMemoryReferences(Component c, AddressSetView set, CodeUnit cu, int opIndex,
			boolean alwaysConfirm) {

		if (set == null || set.isEmpty()) {
			return;
		}

		Address cuAddr = cu.getMinAddress();

		ReferenceManager refMgr = cu.getProgram().getReferenceManager();
		Reference ref = refMgr.getPrimaryReferenceFrom(cuAddr, opIndex);

		String nonMemType = null;
		if (ref != null) {
			if (ref.isStackReference()) {
				nonMemType = "Stack";
			}
			else if (ref.getToAddress().isRegisterAddress()) {
				nonMemType = "Register";
			}
			else if (ref.isExternalReference()) {
				nonMemType = "External";
			}
		}

		String setSize = null;
		long cnt = set.getNumAddresses();
		if (cnt > 100) {
			setSize = "large";
		}
		if (cnt > 200) {
			setSize = "very large";
		}

		RefType rt = RefTypeFactory.getDefaultMemoryRefType(cu, opIndex, null, false);

		if (alwaysConfirm || nonMemType != null || setSize != null) {
			String op = (opIndex == ReferenceManager.MNEMONIC ? "MNEMONIC" : ("OP-" + opIndex));
			String msg = "Add memory references from " + op + " at " + cu.getMinAddress() +
				" to all code units in your selection?\n" + "Reference Type: " + rt.toString();
			if (setSize != null) {
				msg = msg + "\n \nWarning! A " + setSize +
					" number of addresses have been selected!\n";
			}
			if (nonMemType != null) {
				msg =
					msg + "\n \nWarning! Existing " + nonMemType + " reference(s) will be deleted!";
			}
			int rc = OptionDialog.showOptionDialog(c, "Add Memory References", msg, "OK",
				OptionDialog.WARNING_MESSAGE);
			if (rc != OptionDialog.OPTION_ONE) {
				return;
			}
		}

		BackgroundCommand cmd =
			new AddMemRefsCmd(cuAddr, set, rt, SourceType.USER_DEFINED, opIndex);
		tool.executeBackgroundCommand(cmd, cu.getProgram());
	}

	boolean addDefaultReference(Program program, Address fromAddr, int opIndex, Address toAddr,
			RefType refType) {
		Command cmd =
			new AddMemRefCmd(fromAddr, toAddr, refType, SourceType.USER_DEFINED, opIndex, true);
		return tool.execute(cmd, program);
	}

	boolean addDefaultReference(Program program, Address fromAddr, int opIndex, int stackOffset) {
		Command cmd = new AddStackRefCmd(fromAddr, opIndex, stackOffset, SourceType.USER_DEFINED);
		return tool.execute(cmd, program);
	}

	boolean addDefaultReference(Program program, Address fromAddr, int opIndex, Register reg) {
		Command cmd = new AddRegisterRefCmd(fromAddr, opIndex, reg, SourceType.USER_DEFINED);
		return tool.execute(cmd, program);
	}

	/**
	 * Remove specified reference from program
	 */
	void deleteReference(Program program, Reference ref) {
		RemoveReferenceCmd cmd = new RemoveReferenceCmd(ref);
		tool.execute(cmd, program);
	}

	/**
	 * Remove specified set of references
	 */
	void deleteReferences(Program program, Reference[] refs) {
		CompoundCmd cmd = new CompoundCmd("Remove Reference(s)");
		for (Reference ref : refs) {
			cmd.add(new RemoveReferenceCmd(ref));
		}
		tool.execute(cmd, program);
	}

	/**
	 * Update memory reference
	 * 
	 * @return true if update was successful
	 */
	boolean updateReference(Reference editRef, CodeUnit fromCodeUnit, Address toAddr,
			boolean isOffsetRef, long offset, RefType refType) {
		CompoundCmd cmd = new CompoundCmd("Update Memory Reference");
		int opIndex = editRef.getOperandIndex();
		cmd.add(new RemoveReferenceCmd(editRef));
		if (isOffsetRef) {
			cmd.add(new AddOffsetMemRefCmd(fromCodeUnit.getMinAddress(), toAddr, refType,
				SourceType.USER_DEFINED, opIndex, offset));
		}
		else {
			cmd.add(new AddMemRefCmd(fromCodeUnit.getMinAddress(), toAddr, refType,
				SourceType.USER_DEFINED, opIndex, editRef.isPrimary()));
		}
		return tool.execute(cmd, fromCodeUnit.getProgram());
	}

	/**
	 * Add memory reference
	 * 
	 * @param fromCodeUnit
	 * @param opIndex
	 * @param toAddr
	 * @param isOffsetRef
	 * @param offset
	 * @param refType
	 * @return true if add was successful
	 */
	boolean addReference(CodeUnit fromCodeUnit, int opIndex, Address toAddr, boolean isOffsetRef,
			long offset, RefType refType) {

		Address fromAddr = fromCodeUnit.getMinAddress();
		Reference[] refs =
			fromCodeUnit.getProgram().getReferenceManager().getReferencesFrom(fromAddr, opIndex);

		if (refs.length != 0 && !refs[0].isMemoryReference() &&
			!confirmPossibleReferenceRemoval(fromCodeUnit, opIndex, refs[0])) {
			return false;
		}

		Command cmd;
		if (isOffsetRef) {
			cmd = new AddOffsetMemRefCmd(fromAddr, toAddr, refType, SourceType.USER_DEFINED,
				opIndex, offset);
		}
		else {
			cmd = new AddMemRefCmd(fromAddr, toAddr, refType, SourceType.USER_DEFINED, opIndex);
		}
		return tool.execute(cmd, fromCodeUnit.getProgram());
	}

	boolean updateReference(Reference editRef, CodeUnit fromCodeUnit, Register reg,
			RefType refType) {

		Program p = fromCodeUnit.getProgram();

		Address fromAddr = fromCodeUnit.getMinAddress();
		Function f = p.getFunctionManager().getFunctionContaining(fromAddr);
		if (f == null) {
			return false;
		}

		CompoundCmd cmd = new CompoundCmd("Update Register Reference");
		cmd.add(new RemoveReferenceCmd(editRef));
		cmd.add(new AddRegisterRefCmd(fromAddr, editRef.getOperandIndex(), reg, refType,
			SourceType.USER_DEFINED));

		return tool.execute(cmd, p);
	}

	boolean addReference(CodeUnit fromCodeUnit, int opIndex, Register reg, RefType refType) {

		if (!confirmPossibleReferenceRemoval(fromCodeUnit, opIndex, null)) {
			return false;
		}

		Program p = fromCodeUnit.getProgram();

		Address fromAddr = fromCodeUnit.getMinAddress();
		Function f = p.getFunctionManager().getFunctionContaining(fromAddr);
		if (f == null) {
			return false;
		}

		AddRegisterRefCmd cmd =
			new AddRegisterRefCmd(fromAddr, opIndex, reg, refType, SourceType.USER_DEFINED);
		return tool.execute(cmd, p);
	}

	public boolean updateReference(StackReference editRef, CodeUnit fromCodeUnit, int stackOffset,
			RefType refType) {

		Program p = fromCodeUnit.getProgram();

		Address fromAddr = fromCodeUnit.getMinAddress();
		Function f = p.getFunctionManager().getFunctionContaining(fromAddr);
		if (f == null) {
			return false;
		}

		CompoundCmd cmd = new CompoundCmd("Update Stack Reference");
		cmd.add(new RemoveReferenceCmd(editRef));
		cmd.add(new AddStackRefCmd(fromAddr, editRef.getOperandIndex(), stackOffset, refType,
			SourceType.USER_DEFINED));

		return tool.execute(cmd, p);
	}

	public boolean addReference(CodeUnit fromCodeUnit, int opIndex, int stackOffset,
			RefType refType) {

		if (!confirmPossibleReferenceRemoval(fromCodeUnit, opIndex, null)) {
			return false;
		}

		Program p = fromCodeUnit.getProgram();

		Address fromAddr = fromCodeUnit.getMinAddress();
		Function f = p.getFunctionManager().getFunctionContaining(fromAddr);
		if (f == null) {
			return false;
		}

		AddStackRefCmd cmd =
			new AddStackRefCmd(fromAddr, opIndex, stackOffset, refType, SourceType.USER_DEFINED);

		return tool.execute(cmd, p);
	}

	private void buildAddExtRefCmd(CompoundCmd cmd, Program p, Address fromAddr, int opIndex,
			String extName, String path, Address addr, String label, RefType refType) {

		cmd.add(new SetExternalRefCmd(fromAddr, opIndex, extName, label, addr, refType,
			SourceType.USER_DEFINED));

		String existingPath = p.getExternalManager().getExternalLibraryPath(extName);
		if (path != null && path.length() > 0) {
			if (!path.equals(existingPath)) {
				cmd.add(new SetExternalNameCmd(extName, path));
			}
		}
	}

	public boolean updateReference(ExternalReference editRef, CodeUnit fromCodeUnit, String extName,
			String path, Address addr, String label) {

		Program p = fromCodeUnit.getProgram();

		ExternalLocation oldExtLoc = editRef.getExternalLocation();
		String oldExtName = oldExtLoc.getLibraryName();

		CompoundCmd cmd = new CompoundCmd("Update External Reference");

		// TODO: Add RefType entry to External Reference editor panel (assume unchanged to avoid merge conflict)

		// Update performed as ADD since only a single ref will be permitted
		buildAddExtRefCmd(cmd, p, fromCodeUnit.getMinAddress(), editRef.getOperandIndex(), extName,
			path, addr, label, editRef.getReferenceType());

		if (tool.execute(cmd, p)) {
			if (!p.getReferenceManager().getReferencesTo(
				oldExtLoc.getExternalSpaceAddress()).hasNext() &&
				OptionDialog.YES_OPTION == OptionDialog.showYesNoDialog(tool.getActiveWindow(),
					"Delete Unused External Location?",
					"Remove unused external location symbol '" + oldExtLoc.toString() + "'?")) {
				deleteExternalLocation(p, oldExtLoc);

				if (!p.getExternalManager().getExternalLocations(oldExtName).hasNext() &&
					OptionDialog.YES_OPTION == OptionDialog.showYesNoDialog(tool.getActiveWindow(),
						"Delete Unused Library Name?",
						"Remove unused library symbol '" + oldExtName + "'?")) {
					RemoveExternalNameCmd rmCmd = new RemoveExternalNameCmd(oldExtName);
					tool.execute(rmCmd, p);
				}
			}
			return true;
		}
		return false;
	}

	private void deleteExternalLocation(Program p, ExternalLocation extLoc) {
		int txId = p.startTransaction("Delete External Location");
		try {
			p.getSymbolTable().removeSymbolSpecial(extLoc.getSymbol());
		}
		finally {
			p.endTransaction(txId, true);
		}
	}

	public boolean addReference(CodeUnit fromCodeUnit, int opIndex, String extName, String path,
			Address addr, String label) {

		if (!confirmPossibleReferenceRemoval(fromCodeUnit, opIndex, null)) {
			return false;
		}

		Program p = fromCodeUnit.getProgram();

		// TODO: Add RefType entry to External Reference editor panel (infer default for now to avoid merge conflict)

		RefType refType = RefType.DATA;
		if (fromCodeUnit instanceof Instruction) {
			FlowType flowType = ((Instruction) fromCodeUnit).getFlowType();
			if (flowType.isComputed()) {
				if (flowType.isCall()) {
					refType = RefType.COMPUTED_CALL;
				}
				else if (flowType.isJump()) {
					refType = RefType.COMPUTED_JUMP;
				}
			}
			else if (flowType.isCall()) {
				refType = RefType.UNCONDITIONAL_CALL;
			}
			else if (flowType.isJump()) {
				refType = RefType.UNCONDITIONAL_JUMP;
			}
		}

		CompoundCmd cmd = new CompoundCmd("Add External Reference");
		buildAddExtRefCmd(cmd, p, fromCodeUnit.getMinAddress(), opIndex, extName, path, addr, label,
			refType);

		return tool.execute(cmd, p);
	}

	private boolean confirmPossibleReferenceRemoval(CodeUnit fromCodeUnit, int opIndex,
			Reference oldRef) {

		if (oldRef == null) {
			Reference[] refs = fromCodeUnit.getProgram().getReferenceManager().getReferencesFrom(
				fromCodeUnit.getMinAddress(), opIndex);
			if (refs.length != 0) {
				oldRef = refs[0];
			}
			else {
				return true;
			}
		}

		String curType;
		if (oldRef.isStackReference()) {
			curType = "Stack reference";
		}
		else if (oldRef.getToAddress().isRegisterAddress()) {
			curType = "Register reference";
		}
		else if (oldRef.isExternalReference()) {
			curType = "External reference";
		}
		else {
			curType = "Memory reference(s)";
		}

		JComponent parent = editRefDialog.getComponent();
		int choice = OptionDialog.showOptionDialog(parent, "Reference Removal Confirmation",
			"Warning! existing " + curType + " will be removed.", "Continue",
			OptionDialog.WARNING_MESSAGE);
		return (choice != OptionDialog.CANCEL_OPTION);
	}

	@Override
	public void readDataState(SaveState saveState) {
		Element element = saveState.getXmlElement("EditReferenceDialogState");
		if (element != null) {
			if (editRefDialog == null) {
				editRefDialog = new EditReferenceDialog(this);
			}
			SaveState state = new SaveState(element);
			editRefDialog.readDataState(state);
		}
	}

	@Override
	public void writeDataState(SaveState saveState) {
		if (editRefDialog != null) {
			SaveState state = new SaveState("EditReferenceDialogState");
			editRefDialog.writeDataState(state);
			saveState.putXmlElement("EditReferenceDialogState", state.saveToXml());
		}
	}

	ProgramManager getProgramManager() {
		return programMgr;
	}

	public BrowserCodeUnitFormat getCodeUnitFormat() {
		return cuFormat;
	}

	public SymbolInspector getSymbolInspector() {
		return symbolInspector;
	}

	void setDefaultFollowOnLocation(boolean state) {
		defaultFollowOnLocation = state;
	}

	boolean getDefaultFollowOnLocation() {
		return defaultFollowOnLocation;
	}

	void setDefaultGotoReferenceLocation(boolean state) {
		defaultGotoReferenceLocation = state;
	}

	boolean getDefaultGotoReferenceLocation() {
		return defaultGotoReferenceLocation;
	}
}
