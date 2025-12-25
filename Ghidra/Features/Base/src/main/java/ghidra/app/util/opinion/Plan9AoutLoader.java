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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.plan9aout.Plan9AoutHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing Plan9-style A.out executables
 * <p>
 * This style was also used by Plan9-like systems such as 9front, NIX and Inferno.
 *
 * @see <a href="https://9p.io/magic/man2html/6/a.out">Plan 9 manpage</a>
 * @see <a href="https://9p.io/sources/plan9/sys/include/a.out.h">Plan 9 definition header</a>
 */
public class Plan9AoutLoader extends AbstractProgramWrapperLoader {

	public final static String PLAN9_AOUT_NAME = "Plan 9 A.out";

	public static final String OPTION_NAME_BASE_ADDR = "Base Address";

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		Plan9AoutHeader hdr = new Plan9AoutHeader(provider);

		if (hdr.isValid()) {
			final String lang = hdr.getLanguageSpec();
			final String comp = hdr.getCompilerSpec();
			// true means BE, maybe should detect?
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(lang, comp), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		final Plan9AoutHeader header = new Plan9AoutHeader(provider);

		final Plan9AoutProgramLoader loader =
			new Plan9AoutProgramLoader(program, header, monitor, log);
		loader.loadAout(getBaseAddrOffset(options));
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		Address baseAddr = null;

		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(OPTION_NAME_BASE_ADDR)) {
					baseAddr = (Address) option.getValue();
				}
			}
			catch (Exception e) {
				if (e instanceof OptionException) {
					return e.getMessage();
				}
				return "Invalid value for " + optName + " - " + option.getValue();
			}
		}
		if (baseAddr == null) {
			return "Invalid base address";
		}

		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		Address baseAddr = null;

		if (domainObject instanceof Program) {
			Program program = (Program) domainObject;
			AddressFactory addressFactory = program.getAddressFactory();
			if (addressFactory != null) {
				AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
				if (defaultAddressSpace != null) {
					baseAddr = defaultAddressSpace.getAddress(0);
				}
			}
		}

		List<Option> list = new ArrayList<Option>();
		list.add(new Option(OPTION_NAME_BASE_ADDR, baseAddr, Address.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"));

		list.addAll(super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram));
		return list;
	}

	@Override
	public String getName() {
		return PLAN9_AOUT_NAME;
	}

	/**
	 * Retrieves the Address offset given in the "Base Address" option.
	 * Returns 0 if the option could not be found or contains an invalid value.
	 */
	private long getBaseAddrOffset(List<Option> options) {
		Address baseAddr = null;

		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_NAME_BASE_ADDR)) {
					baseAddr = (Address) option.getValue();
				}
			}
		}

		long offset = 0;
		if (baseAddr != null) {
			offset = baseAddr.getOffset();
		}

		return offset;
	}
}
