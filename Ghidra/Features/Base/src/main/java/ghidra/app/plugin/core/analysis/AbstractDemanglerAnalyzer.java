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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import ghidra.app.services.*;
import ghidra.app.util.demangler.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
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

	private static final AddressSetView EXTERNAL_SET = new AddressSet(
		AddressSpace.EXTERNAL_SPACE.getMinAddress(), AddressSpace.EXTERNAL_SPACE.getMaxAddress());

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

		try {
			monitor.setIndeterminate(true);
			// NOTE: demangling of Externals may lose mangled name if original
			// imported name has already been assigned to the External symbol (e.g., ordinal based name)
			return doAdded(program, set, monitor, log);
		}
		finally {
			monitor.setIndeterminate(false);
		}
	}

	private boolean doAdded(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		DemanglerOptions options = getOptions();
		if (!validateOptions(options, log)) {
			log.appendMsg(getName(), "Invalid demangler options--cannot demangle");
			return false;
		}

		// Demangle external symbols after memory symbols.
		// This is done to compensate for cases where the mangled name on externals may be lost
		// after demangling when an alternate Ordinal symbol exists.  The external mangled
		// name is helpful in preserving thunk relationships when a mangled symbols have been
		// placed on a thunk.  It is assumed that analyzer is presented with entire
		// EXTERNAL space in set (all or none).
		boolean demangleExternals = set.contains(EXTERNAL_SET.getMinAddress());
		if (demangleExternals) {
			set = set.subtract(EXTERNAL_SET);
		}

		String baseMonitorMessage = monitor.getMessage();
		int memorySymbolCount =
			demangleSymbols(program, set, 0, baseMonitorMessage, options, log, monitor);
		if (demangleExternals) {
			// process external symbols last
			demangleSymbols(program, EXTERNAL_SET, memorySymbolCount, baseMonitorMessage, options,
				log, monitor);
		}

		return true;
	}

	private int demangleSymbols(Program program, AddressSetView set, int initialCount,
			String baseMonitorMessage, DemanglerOptions options, MessageLog log,
			TaskMonitor monitor) throws CancelledException {

		int count = initialCount;
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator it = symbolTable.getPrimarySymbolIterator(set, true);
		while (it.hasNext()) {
			monitor.checkCanceled();

			if (++count % 100 == 0) {
				monitor.setMessage(baseMonitorMessage + " - " + count + " symbols");
			}

			Symbol symbol = it.next();
			if (skipSymbol(symbol)) {
				continue;
			}

			Address address = symbol.getAddress();
			String mangled = cleanSymbol(address, symbol.getName());
			DemangledObject demangled = demangle(mangled, address, options, log);
			if (demangled != null) {
				apply(program, address, demangled, options, log, monitor);
			}
		}
		return count;
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

		// Someone has already added arguments or return to the function signature.
		// Treatment of thunks must be handled later since thunk relationship may
		// need to be broken
		if (symbol.getSymbolType() == SymbolType.FUNCTION) {
			Function function = (Function) symbol.getObject();
			if (!function.isThunk() &&
				function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS)) {
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
	 * @param address the symbol address
	 * @param options the demangler options
	 * @param log the error log
	 * @return the demangled object; null if unsuccessful
	 */
	protected DemangledObject demangle(String mangled, Address address, DemanglerOptions options,
			MessageLog log) {

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

			log.appendMsg(getName(), "Unable to demangle symbol: " + mangled + " at " + address +
				".  Message: " + e.getMessage());
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
		try {
			if (demangled.applyTo(program, address, options, monitor)) {
				return;
			}
			logApplyErrorMessage(log, demangled, address, null);
		}
		catch (Exception e) {
			logApplyErrorMessage(log, demangled, address, e);
		}

	}

	private void logApplyErrorMessage(MessageLog log, DemangledObject demangled, Address address,
			Exception exception) {

		String message;
		String name;
		if (exception == null) {
			// Eventually, if we switch all errors over to being passed by an exception, then
			// we can eliminate this block of code (and not pass null into this method).
			message = "Unknown error at address " + address;
			name = "\n\t" + demangled.getName();
		}
		else {
			message = ExceptionUtils.getMessage(exception);
			name = StringUtils.EMPTY;
		}

		String className = demangled.getClass().getSimpleName();
		log.appendMsg(getName(), "Apply failure (" + className + ": " + message + ")\n\t" +
			demangled.getMangledString() + name);
	}

	protected String cleanSymbol(Address address, String name) {
		return SymbolUtilities.getCleanSymbolName(name, address);
	}

}
