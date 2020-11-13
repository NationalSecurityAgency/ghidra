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

import ghidra.app.services.*;
import ghidra.app.util.demangler.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The base demangler analyzer.  Implementations of this analyzer will attempt to demangle 
 * symbols in the binary being analyzed.
 * 
 * <P>Default implementations of this class exist for Microsoft and GNU.   These two analyzers will
 * only be enabled when the program being analyzed has an architecture that fits each respective
 * analyzer.  Users can subclass this analyzer to easily control the demangling behavior from 
 * the analyzer UI.
 * 
 * <P>This analyzer will call each implementation's 
 * {@link #doDemangle(String, DemanglerOptions, MessageLog)} method for each symbol.   
 * See the various protected methods of this class for points at which behavior can be overridden.
 * 
 */
public abstract class AbstractDemanglerAnalyzer extends AbstractAnalyzer {

	public AbstractDemanglerAnalyzer(String name, String description) {
		super(name, description, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before().before());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		// override this to control program-specific enablement 
		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		DemanglerOptions options = getOptions();
		if (!validateOptions(options, log)) {
			log.appendMsg(getName(), "Invalid demangler options--cannot demangle");
			return false;
		}

		monitor.initialize(100);

		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator it = symbolTable.getPrimarySymbolIterator(set, true);
		while (it.hasNext()) {
			monitor.checkCanceled();

			Symbol symbol = it.next();
			if (skipSymbol(symbol)) {
				continue;
			}

			Address address = symbol.getAddress();
			String mangled = cleanSymbol(address, symbol.getName());
			DemangledObject demangled = demangle(mangled, options, log);
			if (demangled != null) {
				apply(program, address, demangled, options, log, monitor);
			}

			Address min = set.getMinAddress();
			Address max = set.getMaxAddress();
			int distance = (int) (address.getOffset() - min.getOffset());
			int percent = (int) ((distance / max.getOffset()) * 100);
			monitor.setProgress(percent);
		}

		return true;
	}

	/**
	 * The implementation-specific demangling callback
	 * 
	 * @param mangled the mangled string
	 * @param options the demangler options 
	 * @param log the error log
	 * @return the demangled object; null if demangling was unsuccessful
	 * @throws DemangledException if there is a problem demangling or building the result
	 */
	protected abstract DemangledObject doDemangle(String mangled, DemanglerOptions options,
			MessageLog log) throws DemangledException;

	/**
	 * Called before each analysis request to ensure that the current options (which may have
	 * user-defined input) will work with the current demangler
	 * 
	 * @param options the current options in use
	 * @param log the error log into which error message can be written
	 * @return true if valid
	 */
	protected boolean validateOptions(DemanglerOptions options, MessageLog log) {
		// override to validate custom options for a particular demangler
		return true;
	}

	/**
	 * True if this analyzer should <b>not</b> attempt to demangle the given symbol
	 * 
	 * @param symbol the symbol
	 * @return true to skip the symbol
	 */
	protected boolean skipSymbol(Symbol symbol) {
		if (symbol.getSource() == SourceType.DEFAULT) {
			return true;
		}

		// Only demangle global or external symbols when directly parented to a Library namespace
		Namespace parentNamespace = symbol.getParentNamespace();
		if (symbol.isExternal()) {
			if (!(parentNamespace instanceof Library)) {
				return true;
			}
		}
		else if (!parentNamespace.isGlobal()) {
			return true;
		}

		// Someone has already added arguments or return to the function signature
		if (symbol.getSymbolType() == SymbolType.FUNCTION) {
			Function function = (Function) symbol.getObject();
			if (function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Creates the options for the demangler used by implementations of this analyzer.  This will 
	 * be called before each {@link #added(Program, AddressSetView, TaskMonitor, MessageLog)}
	 * call processes symbols.
	 * 
	 * @return the options 
	 */
	protected DemanglerOptions getOptions() {
		// note: these can be stored in the analyzer subclass and updated when the
		//       analysis options change		
		DemanglerOptions options = new DemanglerOptions();
		options.setApplySignature(true);
		options.setDoDisassembly(true);
		options.setDemangleOnlyKnownPatterns(false);
		return options;
	}

	/**
	 * This calss's default demangle method.  This may be overridden to change how errors are
	 * handled.
	 *  
	 * @param mangled the mangled string
	 * @param options the demangler options
	 * @param log the error log
	 * @return the demangled object; null if unsuccessful
	 */
	protected DemangledObject demangle(String mangled, DemanglerOptions options, MessageLog log) {

		DemangledObject demangled = null;
		try {
			demangled = doDemangle(mangled, options, log);
		}
		catch (Throwable e) {

			if (e instanceof DemangledException) {
				if (((DemangledException) e).isInvalidMangledName()) {
					//ignore invalid names, consider as not an error
					return null;
				}
			}

			log.appendMsg(getName(),
				"Unable to demangle symbol: " + mangled + ".  Message: " + e.getMessage());
			return null;
		}

		return demangled;
	}

	/**
	 * Applies the given demangled object to the program
	 * 
	 * @param program the program
	 * @param address the apply address 
	 * @param demangled the demangled object
	 * @param options the options used during the apply
	 * @param log the error log
	 * @param monitor the task monitor
	 */
	protected void apply(Program program, Address address, DemangledObject demangled,
			DemanglerOptions options, MessageLog log, TaskMonitor monitor) {

		String errorMessage = null;
		try {
			if (demangled.applyTo(program, address, options, monitor)) {
				return;
			}
		}
		catch (Exception e) {
			String message = e.getMessage();
			if (message == null) {
				message = "";
			}
			errorMessage = "\n" + e.getClass().getSimpleName() + ' ' + message;
		}

		String failMessage = " (" + getName() + "/" + demangled.getClass().getName() + ")";
		if (errorMessage != null) {
			failMessage += errorMessage;
		}

		log.appendMsg(getName(), "Failed to apply mangled symbol at " + address + "; name:  " +
			demangled.getMangledString() + failMessage);
	}

	protected String cleanSymbol(Address address, String name) {
		return SymbolUtilities.getCleanSymbolName(name, address);
	}

}
