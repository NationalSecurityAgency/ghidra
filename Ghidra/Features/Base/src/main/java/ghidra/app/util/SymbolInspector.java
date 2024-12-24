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
package ghidra.app.util;

import java.awt.Color;
import java.awt.Component;
import java.util.HashMap;
import java.util.Map;

import docking.options.OptionsService;
import generic.theme.GThemeDefaults.Colors;
import ghidra.GhidraOptions;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.options.ScreenElement;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

/**
 * Class for coloring symbols.
 */
public class SymbolInspector implements OptionsChangeListener {

	private Component repaintComp;
	private ToolOptions optionsObject;
	private Map<String, Object> cache = new HashMap<>();

	/**
	 * Constructs a new symbol inspector
	 * It uses the tool to get the CATEGORY_BROWSER_DISPLAY options
	 * 
	 * @param serviceProvider a service provider for getting services
	 * @param repaintComp the component to repaint when the options change
	 */
	public SymbolInspector(ServiceProvider serviceProvider, Component repaintComp) {
		this(getOptions(serviceProvider), repaintComp);
	}

	/**
	 * Constructs a new symbol inspector
	 * 
	 * @param options the options from which to get colors
	 * @param repaintComp the component to repaint when the options change
	 */
	public SymbolInspector(ToolOptions options, Component repaintComp) {
		this.optionsObject = options;
		this.optionsObject.addOptionsChangeListener(this);
		this.repaintComp = repaintComp;
	}

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_DISPLAY)) {
			if (cache.containsKey(name)) {
				cache.put(name, newValue);
			}
			if (repaintComp != null) {
				repaintComp.repaint();
			}
		}
	}

	/**
	 * Call this when you are done with this inspector and will not use it again.
	 * Cleans up listeners, etc.
	 */
	public void dispose() {
		if (optionsObject != null) {
			optionsObject.removeOptionsChangeListener(this);
			optionsObject = null;
		}
		repaintComp = null;
	}

	/**
	 * Does nothing
	 * @param p the program
	 * @deprecated this method does nothing
	 */
	@Deprecated(since = "11.3", forRemoval = true)
	public void setProgram(Program p) {
		// do nothing
	}

	/**
	 * {@return null}
	 * @deprecated returns null
	 */
	@Deprecated(since = "11.3", forRemoval = true)
	public Program getProgram() {
		return null;
	}

	/**
	 * Returns true if symbol is at a non-existent address
	 * @param s the symbol to check
	 * @return boolean true if symbol is bad
	 */
	public boolean isBadReferenceSymbol(Symbol s) {
		Memory memory = getMemory(s);
		if (memory == null) {
			return true;
		}
		Address a = s.getAddress();
		if (a.isMemoryAddress()) {
			return !memory.contains(s.getAddress());
		}
		return false;
	}

	/**
	 * Returns true if the symbol is on a data item.
	 * @param s the symbol to check
	 * @return boolean true if s is a data symbol
	 */
	public boolean isDataSymbol(Symbol s) {
		if (isBadReferenceSymbol(s)) {
			return false;
		}
		Address addr = s.getAddress();
		Listing listing = getListing(s);
		Data data = listing.getDataContaining(addr);
		return (data != null);
	}

	/**
	 * Returns true if the symbol is on "dead" code
	 * @param s the symbol to check
	 * @return boolean true if the symbol is on dead code
	 */
	public boolean isDeadCodeSymbol(Symbol s) {
		if (isBadReferenceSymbol(s)) {
			return false;
		}
		Program program = s.getProgram();
		ReferenceManager refMgr = program.getReferenceManager();
		return !refMgr.hasReferencesTo(s.getAddress());
	}

	/**
	 * Checks if the given symbol is at an external entry point
	 * @param s the symbol to check
	 * @return boolean true if the symbol is at an external entry point address.
	 */
	public boolean isEntryPointSymbol(Symbol s) {
		if (isBadReferenceSymbol(s)) {
			return false;
		}
		return s.isExternalEntryPoint();
	}

	/**
	 * Checks if the symbol is at a function
	 * @param s the symbol to check.
	 * @return boolean true if there is a function at the symbol's address.
	 */
	public boolean isFunctionSymbol(Symbol s) {
		if (isBadReferenceSymbol(s)) {
			return false;
		}
		return s.getSymbolType() == SymbolType.FUNCTION;
	}

	/**
	 * Checks if the symbol is a function variable
	 * @param s the symbol to check
	 * @return true if s is a function variable symbol
	 */
	public boolean isVariableSymbol(Symbol s) {
		Symbol parent = s.getParentSymbol();
		if (parent == null || !isFunctionSymbol(parent)) {
			return false;
		}
		SymbolType type = s.getSymbolType();
		return type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR ||
			type == SymbolType.GLOBAL_VAR;
	}

	/**
	 * Checks if the symbol is global or local
	 * @param s the symbol to check
	 * @return boolean true if the symbol is global, false if the symbol is
	 * local.
	 */
	public boolean isGlobalSymbol(Symbol s) {
		return s.isGlobal();
	}

	/**
	 * Checks if the symbol is at or inside an instruction
	 * @param s the symbol to check
	 * @return boolean true if the symbol is on an instruction
	 */
	public boolean isInstructionSymbol(Symbol s) {
		if (isBadReferenceSymbol(s)) {
			return false;
		}
		Address addr = s.getAddress();
		Listing listing = getListing(s);
		Instruction instr = listing.getInstructionContaining(addr);
		return (instr != null);
	}

	/**
	 * Checks if the symbol is local
	 * @param s the symbol to check
	 * @return boolean true if the symbol is local, false if it is global
	 */
	public boolean isLocalSymbol(Symbol s) {
		for (Symbol p = s.getParentSymbol(); p != null; p = p.getParentSymbol()) {
			if (p instanceof FunctionSymbol) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if the symbol is not a primary symbol
	 * @param s the symbol to check.
	 * @return boolean true if the symbol is non-primary
	 */
	public boolean isNonPrimarySymbol(Symbol s) {
		if (isBadReferenceSymbol(s)) {
			return false;
		}
		return !s.isPrimary();
	}

	/**
	 * Checks if the symbol is offcut
	 * @param s the symbol to check
	 * @return boolean true if the symbol is offcut
	 */
	public boolean isOffcutSymbol(Symbol s) {
		if (isBadReferenceSymbol(s)) {
			return false;
		}
		Address addr = s.getAddress();
		Listing listing = getListing(s);
		CodeUnit cu = listing.getCodeUnitContaining(addr);
		if (cu != null && cu.getLength() > 1) {
			return cu.getMinAddress().compareTo(addr) < 0;
		}
		return false;
	}

	/**
	 * returns true if the symbol is primary
	 * @param s the symbol to check
	 * @return boolean true if the symbol is primary
	 */
	public boolean isPrimarySymbol(Symbol s) {
		if (isBadReferenceSymbol(s)) {
			return false;
		}
		return s.isPrimary();
	}

	/**
	 * Checks if the symbol is at the beginning of a subroutine.
	 * @param s the symbol to check
	 * @return boolean true if the symbol is at the beginning of a subroutine.
	 */
	public boolean isSubroutineSymbol(Symbol s) {
		if (isBadReferenceSymbol(s)) {
			return false;
		}
		Reference[] refsTo = s.getReferences(null);
		for (Reference element : refsTo) {
			if (element.getReferenceType().isCall()) {
				return true;
			}
		}
		return false;
	}

	public boolean isExternalSymbol(Symbol s) {
		return s.getAddress().isExternalAddress();
	}

	/**
	 * Gets the color and style used to render the given symbol.  Calling this method is
	 * faster than calling {@link #getColor(Symbol)} and {@link #getStyle(Symbol)}
	 * separately.
	 * 
	 * @param s the symbol
	 * @return the color and style
	 */
	public ColorAndStyle getColorAndStyle(Symbol s) {
		ScreenElement se = getScreenElement(s);
		Color color = getColor(se);
		int style = getStyle(se);
		return new ColorAndStyle(color, style);
	}

	/**
	 * Gets the color and style used to render the given reference.  Calling this method is
	 * faster than calling {@link #getColor(Symbol)} and {@link #getStyle(Symbol)}
	 * separately.
	 * 
	 * @param p the program
	 * @param r the reference
	 * @return the color and style
	 */
	public ColorAndStyle getColorAndStyle(Program p, Reference r) {
		ScreenElement se = getScreenElement(p, r);
		if (se == null) {
			return null;
		}
		Color color = getColor(se);
		int style = getStyle(se);
		return new ColorAndStyle(color, style);
	}

	/**
	 * Get the color used to render the given symbol.
	 * @param s symbol to inspect
	 * @return Color for the symbol
	 */
	public Color getColor(Symbol s) {
		return getColor(getScreenElement(s));
	}

	/**
	 * Get the style used to render the given symbol
	 * @param s symbol to inspect
	 * @return the style for the symbol
	 */
	public int getStyle(Symbol s) {
		return getStyle(getScreenElement(s));
	}

	/**
	 * Get the ScreenElement corresponding to the type of the symbol
	 * @param s the symbol to inspect
	 * @return the screen element
	 */
	public ScreenElement getScreenElement(Symbol s) {

		if (s == null) {
			return null;
		}

		if (isExternalSymbol(s)) {
			return getExternalScreenElement(s);
		}
		else if (isBadReferenceSymbol(s)) {
			return OptionsGui.BAD_REF_ADDR;
		}
		else if (isOffcutSymbol(s)) {
			return OptionsGui.XREF_OFFCUT;
		}
		else if (isEntryPointSymbol(s)) {
			return OptionsGui.ENTRY_POINT;
		}
		else if (isDeadCodeSymbol(s)) {
			return OptionsGui.LABELS_UNREFD;
		}
		else if (isFunctionSymbol(s)) {
			Function f = (Function) s.getObject();
			return getFunctionScreenElement(f);
		}
		else if (isVariableSymbol(s)) {
			if (s.getSymbolType() == SymbolType.PARAMETER) {
				Function function = (Function) s.getParentNamespace();
				return function.hasCustomVariableStorage() ? OptionsGui.PARAMETER_CUSTOM
						: OptionsGui.PARAMETER_DYNAMIC;
			}
			return OptionsGui.VARIABLE;
		}
		else if (isPrimarySymbol(s)) {
			return OptionsGui.LABELS_PRIMARY;
		}
		else if (isLocalSymbol(s)) {
			return OptionsGui.LABELS_LOCAL;
		}
		else if (isNonPrimarySymbol(s)) {
			return OptionsGui.LABELS_NON_PRIMARY;
		}
		return null;
	}

	/**
	 * Get the ScreenElement corresponding to the type of the reference.
	 * @param p the program
	 * @param r the reference to inspect
	 * @return the screen element
	 */
	public ScreenElement getScreenElement(Program p, Reference r) {
		if (r.isExternalReference()) {
			ExternalLocation extLoc = ((ExternalReference) r).getExternalLocation();
			String libName = extLoc.getLibraryName();
			return getExternalPathScreenElement(p, libName);
		}
		return null;
	}

	public Color getOffcutSymbolColor() {
		return getColor(OptionsGui.XREF_OFFCUT);
	}

	public int getOffcutSymbolStyle() {
		return getStyle(OptionsGui.XREF_OFFCUT);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private Listing getListing(Symbol s) {
		Program p = s.getProgram();
		if (p != null) {
			return p.getListing();
		}
		return null; // not sure if this can happen
	}

	private Memory getMemory(Symbol s) {
		Program p = s.getProgram();
		if (p != null) {
			return p.getMemory();
		}
		return null; // not sure if this can happen
	}

	private ScreenElement getExternalScreenElement(Symbol s) {

		Program p = s.getProgram();
		String libName = getExternalName(s);
		return getExternalPathScreenElement(p, libName);
	}

	private ScreenElement getExternalPathScreenElement(Program p, String libName) {

		ExternalManager externalManager = p.getExternalManager();
		if (Library.UNKNOWN.equals(libName)) {
			return OptionsGui.EXT_REF_UNRESOLVED;
		}

		String path = externalManager.getExternalLibraryPath(libName);
		if (path == null || path.length() == 0) {
			return OptionsGui.EXT_REF_UNRESOLVED;
		}
		return OptionsGui.EXT_REF_RESOLVED;
	}

	private ScreenElement getFunctionScreenElement(Function function) {
		if (function == null || !function.isThunk()) {
			return OptionsGui.FUN_NAME;
		}

		// override function name color for external thunks which are not linked
		Function thunkedFunction = function.getThunkedFunction(true);
		if (thunkedFunction == null) {
			return OptionsGui.EXT_REF_UNRESOLVED;
		}
		else if (thunkedFunction.isExternal()) {
			ExternalLocation location = thunkedFunction.getExternalLocation();
			String libName = location.getLibraryName();
			return getExternalPathScreenElement(function.getProgram(), libName);
		}

		return OptionsGui.FUN_NAME;
	}

	private String getExternalName(Symbol s) {
		if (!s.isExternal()) {
			return null;
		}
		if (s.getSymbolType() == SymbolType.LIBRARY) {
			return s.getName();
		}
		Symbol parent = s.getParentSymbol();
		while (parent.getSymbolType() != SymbolType.GLOBAL) {
			if (parent.getSymbolType() == SymbolType.LIBRARY) {
				return parent.getName();
			}
			parent = parent.getParentSymbol();
		}
		return null;
	}

	private static ToolOptions getOptions(ServiceProvider serviceProvider) {
		OptionsService service = serviceProvider.getService(OptionsService.class);
		return service.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
	}

	private Color getColor(ScreenElement se) {
		if (se == null) {
			return Colors.FOREGROUND;
		}
		return se.getDefaultColor();
	}

	private int getStyle(ScreenElement se) {
		if (se == null) {
			return -1;
		}
		String optionName = se.getStyleOptionName();
		Integer style = (Integer) cache.get(optionName);
		if (style == null) {
			style = optionsObject.getInt(optionName, -1);
			cache.put(optionName, style);
		}
		return style.intValue();
	}
}
