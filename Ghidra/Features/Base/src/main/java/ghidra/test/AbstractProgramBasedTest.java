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

import java.util.ArrayList;
import java.util.List;

import org.junit.After;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.AssertException;
import util.CollectionUtils;
import utility.function.ExceptionalConsumer;
import utility.function.ExceptionalFunction;

/**
 * A convenience base class for creating tests that use the default tool and open a program.
 * This class will create for you a tool, a {@link TestEnv} and will open the program 
 * specified by {@link #getProgramName()}.
 * 
 * <P>To use this class, you must call {@link #initialize()} from your test or <code>setUp</code> 
 * method.
 * 
 * <P>Note: if you are loading a pre-existing program, then simply override 
 * {@link #getProgramName()}.  Alternatively, if you are building a program, then override
 * {@link #getProgram()} and return it there.
 */
public abstract class AbstractProgramBasedTest extends AbstractGhidraHeadedIntegrationTest {

	protected TestEnv env;
	protected PluginTool tool;
	protected Program program;
	protected CodeBrowserPlugin codeBrowser;

	protected String getProgramName() {
		throw new AssertException(
			"You must override getProgramName() if you are not building your own program manually");
	}

	protected void initialize() throws Exception {

		env = new TestEnv();
		program = getProgram();

		tool = env.launchDefaultTool(program);
		codeBrowser = getPlugin(tool, CodeBrowserPlugin.class);
	}

	/**
	 * Override this method if you need to build your own program.
	 * 
	 * @return the program to use for this test.
	 * @throws Exception if an exception is thrown opening the program
	 */
	protected Program getProgram() throws Exception {
		return env.getProgram(getProgramName());
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	public void assertCurrentAddress(Address expected) {
		codeBrowser.updateNow();
		waitForSwing();
		ProgramLocation loc = codeBrowser.getCurrentLocation();
		Address actual = loc.getAddress();
		assertEquals("Listing is not at the expected address", expected, actual);
	}

	public Address addr(long offset) {
		return addr(program, offset);
	}

	public Address addr(String offset) {
		return addr(program, offset);
	}

	public Address addr(Program p, long offset) {
		AddressFactory addrMap = program.getAddressFactory();
		AddressSpace space = addrMap.getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	public Address addr(Program p, String offset) {
		AddressFactory addrMap = p.getAddressFactory();
		AddressSpace space = addrMap.getDefaultAddressSpace();
		try {
			return space.getAddress(offset);
		}
		catch (AddressFormatException e) {
			throw new AssertException("Unable to create address from String '" + offset + "'", e);
		}
	}

	public void goTo(long offset) {
		goTo(tool, program, addr(offset));
	}

	public void goTo(String offset) {
		goTo(tool, program, addr(offset));
	}

	public AddressRange range(long from, long to) {
		AddressRangeImpl range = new AddressRangeImpl(addr(from), addr(to));
		return range;
	}

	public void showProvider(String name) {
		showProvider(tool, name);
	}

	public Function function(Address addr) {
		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionContaining(addr);
		return f;
	}

	public List<Address> addrs(long... offsets) {
		List<Address> result = new ArrayList<>();
		for (long offset : offsets) {
			result.add(addr(offset));
		}
		return result;
	}

	public AddressSet toAddressSet(long... offsets) {
		List<Address> list = addrs(offsets);
		AddressSet addrs = toAddressSet(list);
		return addrs;
	}

	public List<Address> addrs(Address... addrs) {
		return CollectionUtils.asList(addrs);
	}

	public void goTo(Address a) {
		goTo(tool, program, a);
	}

	/**
	 * Provides a convenient method for modifying the current program, handling the transaction
	 * logic. 
	 * 
	 * @param callback the code to execute
	 */
	public <E extends Exception> void modifyProgram(ExceptionalConsumer<Program, E> callback) {
		assertNotNull("Program cannot be null", program);

		boolean commit = false;
		int tx = program.startTransaction("Test");
		try {
			callback.accept(program);
			commit = true;
		}
		catch (Exception e) {
			failWithException("Exception modifying program '" + program.getName() + "'", e);
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}

	/**
	 * Provides a convenient method for modifying the current program, handling the transaction
	 * logic and returning a new item as a result.
	 * 
	 * @param f the function for modifying the program and creating the desired result
	 * @return the result
	 */
	public <R, E extends Exception> R createInProgram(ExceptionalFunction<Program, R, E> f) {
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
}
