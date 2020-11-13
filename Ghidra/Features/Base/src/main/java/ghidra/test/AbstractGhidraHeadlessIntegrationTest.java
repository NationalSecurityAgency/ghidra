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
package ghidra.test;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.*;

import docking.test.AbstractDockingTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.script.GhidraScriptConstants;
import ghidra.app.services.GoToService;
import ghidra.framework.*;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.mgr.ServiceManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.RollbackException;
import junit.framework.AssertionFailedError;
import utility.application.ApplicationLayout;
import utility.function.ExceptionalCallback;
import utility.function.ExceptionalFunction;

public abstract class AbstractGhidraHeadlessIntegrationTest extends AbstractDockingTest {

	private static final String PROJECT_NAME_SUFFIX =
		BATCH_MODE ? "_BatchTestProject" : "_DevTestProject";
	public static final String PROJECT_NAME = createProjectName();

	private static String createProjectName() {
		File repoDirectory = TestApplicationUtils.getInstallationDirectory();
		return repoDirectory.getName() + PROJECT_NAME_SUFFIX;
	}

	private static Language SLEIGH_X86_64_LANGUAGE;
	private static Language SLEIGH_X86_LANGUAGE;
	private static Language SLEIGH_8051_LANGUAGE;
	private static Language Z80_LANGUAGE;

	public AbstractGhidraHeadlessIntegrationTest() {
		super();

		// Ensure that all error messages do NOT use a gui popup, and instead are routed to the
		// console.
		setErrorGUIEnabled(false);
	}

	@Override
	protected ApplicationLayout createApplicationLayout() {
		try {
			return new GhidraTestApplicationLayout(new File(getTestDirectoryPath()));
		}
		catch (IOException e) {
			throw new AssertException(e);
		}
	}

	@Override
	protected ApplicationConfiguration createApplicationConfiguration() {
		return new HeadlessGhidraApplicationConfiguration();
	}

	@Override
	protected void initializeSystemProperties() {

		super.initializeSystemProperties();

		// don't let scripts step on each other as tests are writing source files
		System.setProperty(GhidraScriptConstants.USER_SCRIPTS_DIR_PROPERTY, getTestDirectoryPath());
	}

	public static boolean deleteProject(String directory, String name) {
		return ProjectTestUtils.deleteProject(directory, name);
	}

	/**
	 * Get the language and compiler spec associated with an old language name string.
	 * If the language no longer exists, and suitable replacement language will be returned
	 * if found.  If no language is found, an exception will be thrown.
	 * @param oldLanguageName old language name string
	 * @return the language compiler and spec
	 * @throws LanguageNotFoundException if the language is not found
	 */
	public static LanguageCompilerSpecPair getLanguageCompilerSpecPair(String oldLanguageName)
			throws LanguageNotFoundException {
		LanguageCompilerSpecPair pair =
			OldLanguageMappingService.lookupMagicString(oldLanguageName, true);
		if (pair == null) {
			throw new LanguageNotFoundException("Old language not found: " + oldLanguageName);
		}
		return pair;
	}

	// TODO add methods:
	// createDefaultToyProgram() with no params	
	// createDefaultX86Program() with no params
	// createDefaultX86ProgramBuilder() with no params
	// createClassicNotepadProgram()

	/**
	 * Creates an in-memory program with the given language
	 * @param name the program name
	 * @param languageString a language string of the format <code>x86:LE:32:default</code>
	 * @param consumer a consumer for the program
	 * @return a new program
	 * @throws Exception if there is any issue creating the language
	 */
	public static ProgramDB createDefaultProgram(String name, String languageString,
			Object consumer) throws Exception {
		if (consumer == null) {
			throw new IllegalArgumentException("null consumer not permitted");
		}
		ProgramBuilder builder = new ProgramBuilder(name, languageString, consumer);
		ProgramDB p = builder.getProgram();
		return p;
	}

	/**
	 * Creates an in-memory program with the given language
	 * @param name the program name
	 * @param languageString a language string of the format <code>x86:LE:32:default</code>
	 * @param compilerSpecID the ID
	 * @param consumer a consumer for the program
	 * @return a new program
	 * @throws Exception if there is any issue creating the language
	 */
	public static ProgramDB createDefaultProgram(String name, String languageString,
			String compilerSpecID, Object consumer) throws Exception {
		if (consumer == null) {
			throw new IllegalArgumentException("null consumer not permitted");
		}
		ProgramBuilder builder = new ProgramBuilder(name, languageString, compilerSpecID, consumer);
		ProgramDB p = builder.getProgram();
		return p;
	}

	/**
	 * Run a command against the specified program within a transaction.
	 * The transaction will be committed unless the command throws a RollbackException.
	 * 
	 * @param program the program
	 * @param cmd the command to apply
	 * @return result of command applyTo method
	 * @throws RollbackException thrown if thrown by command applyTo method
	 */
	public static boolean applyCmd(Program program, Command cmd) throws RollbackException {
		int txId = program.startTransaction(cmd.getName());
		boolean commit = true;
		try {
			boolean status = cmd.applyTo(program);
			program.flushEvents();
			waitForSwing();

			if (!status) {
				Msg.error(null, "Could not apply command: " + cmd.getStatusMsg());
			}

			return status;
		}
		catch (RollbackException e) {
			commit = false;
			throw e;
		}
		finally {
			program.endTransaction(txId, commit);
		}
	}

	/**
	 * Provides a convenient method for modifying the current program, handling the transaction
	 * logic. 
	 * 
	 * @param p the program
	 * @param c the code to execute
	 */
	public static <E extends Exception> void tx(Program p, ExceptionalCallback<E> c) {
		int txId = p.startTransaction("Test - Function in Transaction");
		boolean commit = true;
		try {
			c.call();
			p.flushEvents();
			waitForSwing();
		}
		catch (Exception e) {
			commit = false;
			failWithException("Exception modifying program '" + p.getName() + "'", e);
		}
		finally {
			p.endTransaction(txId, commit);
		}
	}

	/**
	 * Provides a convenient method for modifying the current program, handling the transaction
	 * logic.   This method is calls {@link #tx(Program, ExceptionalCallback)}, but helps with
	 * semantics.
	 * 
	 * @param p the program
	 * @param c the code to execute
	 */
	public static <E extends Exception> void modifyProgram(Program p, ExceptionalCallback<E> c) {
		tx(p, c);
	}

	/**
	 * Provides a convenient method for modifying the current program, handling the transaction
	 * logic and returning a new item as a result
	 * 
	 * @param program the program
	 * @param f the function for modifying the program and creating the desired result
	 * @return the result
	 */
	public <R, E extends Exception> R modifyProgram(Program program,
			ExceptionalFunction<Program, R, E> f) {
		assertNotNull("Program cannot be null", program);

		R result = null;
		boolean commit = false;
		int tx = program.startTransaction("Test");
		try {
			result = f.apply(program);
			commit = true;
		}
		catch (Exception e) {
			failWithException("Exception modifying program '" + program.getName() + "'", e);
		}
		finally {
			program.endTransaction(tx, commit);
		}
		return result;
	}

	/**
	 * Undo the last transaction on the domain object and wait for all events to be flushed.
	 * @param dobj The domain object upon which to perform the undo.
	 * @param wait if true, wait for undo to fully complete in Swing thread.
	 * If a modal dialog may result from this undo, wait should be set false.
	 */
	public static void undo(UndoableDomainObject dobj, boolean wait) {
		Runnable r = () -> {
			try {
				dobj.undo();
				dobj.flushEvents();
			}
			catch (IOException e) {
				Msg.error(AbstractGhidraHeadlessIntegrationTest.class,
					"Exception performing undo operation", e);
			}
		};
		runSwing(r, wait);
		if (wait) {
			waitForSwing();
		}
	}

	/**
	 * Redo the last undone transaction on the domain object and wait for all
	 * events to be flushed.
	 * @param dobj The domain object upon which to perform the redo.
	 * @param wait if true, wait for redo to fully complete in Swing thread.
	 * If a modal dialog may result from this redo, wait should be set false.
	 */
	public static void redo(UndoableDomainObject dobj, boolean wait) {
		Runnable r = () -> {
			try {
				dobj.redo();
				dobj.flushEvents();
			}
			catch (IOException e) {
				Msg.error(AbstractGhidraHeadlessIntegrationTest.class,
					"Exception performing redo operation", e);
			}
		};
		runSwing(r, wait);
		if (wait) {
			waitForSwing();
		}
	}

	/**
	 * Undo the last transaction on the domain object and wait for all
	 * events to be flushed.
	 * @param dobj The domain object upon which to perform the undo.
	 */
	public static void undo(final UndoableDomainObject dobj) {
		undo(dobj, true);
	}

	/**
	 * Redo the last undone transaction on domain object and wait for all
	 * events to be flushed.
	 * @param dobj The domain object upon which to perform the redo.
	 */
	public static void redo(final UndoableDomainObject dobj) {
		redo(dobj, true);
	}

	/**
	 * Undo the last 'count' transactions on the domain object and wait for all
	 * events to be flushed.
	 * @param dobj The domain object upon which to perform the undo.
	 * @param count number of transactions to undo
	 */
	public static void undo(UndoableDomainObject dobj, int count) {
		for (int i = 0; i < count; ++i) {
			undo(dobj);
		}
	}

	/**
	 * Redo the last 'count' undone transactions on the domain object and wait for all
	 * events to be flushed.
	 * @param dobj The domain object upon which to perform the redo.
	 * @param count number of transactions to redo
	 */
	public static void redo(UndoableDomainObject dobj, int count) {
		for (int i = 0; i < count; ++i) {
			redo(dobj);
		}
	}

	public static <T extends Plugin> T getPlugin(PluginTool tool, Class<T> c) {
		List<Plugin> list = tool.getManagedPlugins();
		Iterator<Plugin> it = list.iterator();
		while (it.hasNext()) {
			Plugin p = it.next();
			if (p.getClass() == c) {
				return c.cast(p);
			}
		}
		return null;
	}

	public AddressSet toAddressSet(List<Address> addrs) {
		AddressSet set = new AddressSet();
		for (Address addr : addrs) {
			set.add(addr);
		}
		return set;
	}

	public AddressSet toAddressSet(Address start, Address end) {
		AddressSet set = new AddressSet();
		set.addRange(start, end);
		return set;
	}

	public AddressSet toAddressSet(AddressRange... ranges) {
		AddressSet set = new AddressSet();
		for (AddressRange range : ranges) {
			set.add(range);
		}
		return set;
	}

	public void goTo(PluginTool tool, Program p, Address addr) {

		GoToService goTo = tool.getService(GoToService.class);
		if (goTo != null) {
			goTo.goTo(addr);
			waitForSwing();
			return;
		}

		tool.firePluginEvent(
			new ProgramLocationPluginEvent("Test", new ProgramLocation(p, addr), p));
		waitForSwing();
	}

	public void goTo(PluginTool tool, Program p, String addrString) {
		AddressFactory factory = p.getAddressFactory();
		Address addr = factory.getAddress(addrString);
		tool.firePluginEvent(
			new ProgramLocationPluginEvent("Test", new ProgramLocation(p, addr), p));
		waitForSwing();
	}

	public void makeSelection(PluginTool tool, Program p, List<Address> addrs) {
		AddressSet set = toAddressSet(addrs);
		makeSelection(tool, p, set);
	}

	public void makeSelection(PluginTool tool, Program p, Address from, Address to) {
		ProgramSelection selection = new ProgramSelection(from, to);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, p));
		waitForSwing();
	}

	public void makeSelection(PluginTool tool, Program p, Address... addrs) {
		AddressSet set = toAddressSet(Arrays.asList(addrs));
		makeSelection(tool, p, set);
	}

	public void makeSelection(PluginTool tool, Program p, AddressRange... ranges) {
		AddressSet set = toAddressSet(ranges);
		makeSelection(tool, p, set);
	}

	public void makeSelection(PluginTool tool, Program p, AddressSetView addresses) {
		ProgramSelection selection = new ProgramSelection(addresses);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, p));
		waitForSwing();
	}

	/**
	 * Returns the global symbol with the given name if and only if it is the only
	 * global symbol with that name.
	 * 
	 * @param program the program to search.
	 * @param name the name of the global symbol to find.
	 * @return  the global symbol with the given name if and only if it is the only one.
	 */
	public Symbol getUniqueSymbol(Program program, String name) {
		return getUniqueSymbol(program, name, null);
	}

	/**
	 * Returns the symbol in the given namespace with the given name if and only if it is the only
	 * symbol in that namespace with that name.
	 * 
	 * @param program the program to search.
	 * @param name the name of the symbol to find.
	 * @param namespace the parent namespace; may be null
	 * @return  the symbol with the given name if and only if it is the only one in that namespace
	 */
	public Symbol getUniqueSymbol(Program program, String name, Namespace namespace) {
		List<Symbol> symbols = program.getSymbolTable().getSymbols(name, namespace);
		if (symbols.size() == 1) {
			return symbols.get(0);
		}
		return null;
	}

	/**
	 * A convenience method that allows you to open the given program in a default tool, 
	 * navigating to the given address. 
	 * 
	 * <P>Note: this is a blocking operation.  Your test will not proceed while this method is
	 * sleeping. 
	 * 
	 * <P><B>Do not leave this call in your test when committing changes.</B>
	 * @param p the program
	 * @param address the address
	 * 
	 * @throws Exception if there is an issue create a {@link TestEnv}
	 */
	public void debugProgramInTool(Program p, String address) throws Exception {

		if (BATCH_MODE) {
			// Nightly tests do not need manual debugging
			throw new AssertionFailedError(
				"Take out the call to this method--it is for debugging only");
		}

		long duration = 5; // minutes
		TestEnv env = new TestEnv();
		try {
			PluginTool tool = env.launchDefaultTool(p);
			CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
			if (address != null) {
				plugin.goToField(p.getAddressFactory().getAddress(address), "Address", 0, 0);
			}
			// Place breakpoint on next line when this method is used for diagnostics
			Msg.info(this, "Opened test program in tool");

			// Sleep for a while so the user can inspect the program.  Once the sleep is finished,
			// tool and program will be closed.
			long minutesInMillis = 60 * 1000 * duration;
			sleep(minutesInMillis);

			throw new AssertionFailedError(
				"Take out the call to this method--it is for debugging only");
		}
		finally {
			env.dispose();
		}
	}

	/**
	 * Waits for a launched script to complete by using the given listener. 
	 * 
	 * @param listener the listener used to track script progress
	 * @param timeoutMS the max time to wait; failing if exceeded
	 */
	public void waitForScriptCompletion(ScriptTaskListener listener, long timeoutMS) {
		String scriptName = listener.getScriptName();
		long start = System.currentTimeMillis();
		Msg.debug(this, "Waiting for script " + scriptName + ": " + new Date(start));
		while (!listener.isCompleted()) {
			sleep(DEFAULT_WAIT_DELAY);
			long currentTime = System.currentTimeMillis();
			if (currentTime - start > timeoutMS) {
				Msg.error(this, "Timeout on script: " + scriptName + ": " + new Date(currentTime));
				throw new RuntimeException("Timeout waiting for task to complete");
			}
		}
		Msg.debug(this,
			"Script " + scriptName + " completed: " + new Date(System.currentTimeMillis()));
	}

	/**
	 * Replaces the given implementations of the provided service class with the given class.
	 * 
	 * @param tool the tool whose services to update (optional)
	 * @param service the service to override
	 * @param replacement the new version of the service
	 * @param <T> the service type
	 */
	@SuppressWarnings("unchecked")
	public static <T> void replaceService(PluginTool tool, Class<? extends T> service,
			T replacement) {

		ServiceManager serviceManager = (ServiceManager) getInstanceField("serviceMgr", tool);

		List<Class<?>> extentions =
			(List<Class<?>>) getInstanceField("extensionPoints", ClassSearcher.class);
		Set<Class<?>> set = new HashSet<>(extentions);
		Iterator<Class<?>> iterator = set.iterator();
		while (iterator.hasNext()) {
			Class<?> c = iterator.next();
			if (service.isAssignableFrom(c)) {
				iterator.remove();
				T instance = tool.getService(service);
				serviceManager.removeService(service, instance);
			}
		}

		set.add(replacement.getClass());
		serviceManager.addService(service, replacement);

		List<Class<?>> newExtensionPoints = new ArrayList<>(set);
		setInstanceField("extensionPoints", ClassSearcher.class, newExtensionPoints);
	}

//==================================================================================================
// Language Methods
//==================================================================================================

	/**
	 * Get language service used for testing.
	 * @return language service.
	 */
	public synchronized static LanguageService getLanguageService() {
		return DefaultLanguageService.getLanguageService();
	}

	public static Language getSLEIGH_X86_LANGUAGE() {
		if (SLEIGH_X86_LANGUAGE == null) {
			try {
				SLEIGH_X86_LANGUAGE =
					getLanguageService().getDefaultLanguage(TestProcessorConstants.PROCESSOR_X86);
			}
			catch (LanguageNotFoundException e) {
				// don't care
			}
		}
		return SLEIGH_X86_LANGUAGE;
	}

	public static Language getSLEIGH_X86_64_LANGUAGE() {
		if (SLEIGH_X86_64_LANGUAGE == null) {
			try {
				SLEIGH_X86_64_LANGUAGE =
					getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
			}
			catch (LanguageNotFoundException e) {
				// don't care
			}
		}
		return SLEIGH_X86_64_LANGUAGE;
	}

	public static Language getSLEIGH_8051_LANGUAGE() {
		if (SLEIGH_8051_LANGUAGE == null) {
			try {

				SLEIGH_8051_LANGUAGE =
					getLanguageService().getDefaultLanguage(TestProcessorConstants.PROCESSOR_8051);
			}
			catch (LanguageNotFoundException e) {
				// don't care
			}
		}
		return SLEIGH_8051_LANGUAGE;
	}

	public static Language getZ80_LANGUAGE() {
		if (Z80_LANGUAGE == null) {
			try {
				Z80_LANGUAGE =
					getLanguageService().getDefaultLanguage(TestProcessorConstants.PROCESSOR_Z80);
			}
			catch (LanguageNotFoundException e) {
				// don't care
			}
		}
		return Z80_LANGUAGE;
	}
}
