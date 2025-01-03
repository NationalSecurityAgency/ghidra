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

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import generic.ULongSpan;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.Project;
import ghidra.framework.store.LockException;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class JitLogLoader extends AbstractProgramLoader {
	public final static String JIT_LOG_NAME = "OpenJDK 17 JIT compilation log";

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		return getLanguageService().getLanguageCompilerSpecPairs(
			new LanguageCompilerSpecQuery(null, null, null, null, null))
				.stream()
				.map(lcs -> new LoadSpec(this, 0, lcs, false))
				.toList();
	}

	@Override
	public String getName() {
		return JIT_LOG_NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.UNTARGETED_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 100;
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ByteProvider provider, String loadedName,
			Project project, String projectFolderPath, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Object consumer, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		CompilerSpec cSpec = pair.getCompilerSpec();
		Language language = cSpec.getLanguage();
		Program program =
			createProgram(provider, loadedName, null, getName(), language, cSpec, consumer);
		boolean success = false;
		try {
			loadInto(provider, loadSpec, options, log, program, monitor);
			success = true;
			createDefaultMemoryBlocks(program, language, log);
		}
		finally {
			if (!success) {
				program.release(consumer);
				program = null;
			}
		}
		List<Loaded<Program>> results = new ArrayList<>();
		if (program != null) {
			results.add(new Loaded<>(program, loadedName, projectFolderPath));
		}
		return results;
	}

	static class JitMethod {
		final String name;

		SemisparseByteArray bytes = new SemisparseByteArray();
		Map<Address, String> comments = new HashMap<>();

		public JitMethod(String name) {
			this.name = name;
		}

		void appendComment(Address address, String line) {
			comments.compute(address, (a, c) -> c == null ? line : c + "\n" + line);
		}
	}

	List<JitMethod> methods = new ArrayList<>();
	AddressSet fullSet = new AddressSet();

	static final Pattern PAT_METHOD =
		Pattern.compile("\\s*#\\s*\\{method\\}\\s*\\{0x[0-9A-Fa-f]+\\}(?<name>.*)");
	static final Pattern PAT_COMMENT =
		Pattern.compile("\\s*0x(?<addrHex>[0-9A-Fa-f]+):\\s*;(?<comment>.*)");
	static final Pattern PAT_BYTES =
		Pattern.compile("\\s*0x(?<addrHex>[0-9A-Fa-f]+):\\s*(?<bytes>[\\s\\|0-9A-Fa-f]+)");

	@Override
	protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.setMessage("Reading lines");
		JitMethod curMethod = null;
		String line;
		try (BufferedReader in =
			new BufferedReader(new InputStreamReader(provider.getInputStream(0)))) {
			while (null != (line = in.readLine())) {
				Matcher matcher;
				monitor.checkCanceled();

				matcher = PAT_METHOD.matcher(line);
				if (matcher.matches()) {
					putMethod(curMethod, program);
					curMethod = new JitMethod(matcher.group("name")
							.replace("&apos;", "'")
							.replace("&lt;", "<")
							.replace("&gt;", ">"));
					continue;
				}
				if (curMethod == null) {
					continue;
				}
				matcher = PAT_COMMENT.matcher(line);
				if (matcher.matches()) {
					Address address =
						program.getAddressFactory().getAddress(matcher.group("addrHex"));
					curMethod.appendComment(address, matcher.group("comment"));
				}
				matcher = PAT_BYTES.matcher(line);
				if (matcher.matches()) {
					Address address =
						program.getAddressFactory().getAddress(matcher.group("addrHex"));
					curMethod.bytes.putData(address.getOffset(),
						NumericUtilities.convertStringToBytes(
							matcher.group("bytes").replace(" ", "").replace("|", "")));
				}
			}
		}
		putMethod(curMethod, program);

		monitor.setMaximum(fullSet.getNumAddresses() + methods.size());

		monitor.setMessage("Creating blocks");
		for (AddressRange range : fullSet) {
			monitor.checkCanceled();
			try {
				program.getMemory()
						.createInitializedBlock("block" + range.getMinAddress(),
							range.getMinAddress(), range.getLength(), (byte) 0, monitor, false);
			}
			catch (AddressOverflowException | LockException | IllegalArgumentException
					| MemoryConflictException e) {
				log.appendMsg("Could not create block " + range + ": " + e);
			}
			monitor.incrementProgress(1);
		}

		monitor.setMessage("Creating methods");

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		for (JitMethod method : methods) {
			monitor.checkCanceled();
			AddressSet body = new AddressSet();
			for (ULongSpan span : method.bytes.getInitialized(0, -1).spans()) {
				body.add(space.getAddress(span.min()), space.getAddress(span.max()));
				if (span.length() > Integer.MAX_VALUE) {
					log.appendMsg("Method too large: " + method.name);
					continue;
				}
				byte[] data = new byte[(int) span.length()];
				method.bytes.getData(span.min(), data);
				try {
					program.getMemory().setBytes(space.getAddress(span.min()), data);
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					log.appendMsg("Could not write bytes " + span + ": " + e);
				}
			}
			for (Map.Entry<Address, String> ent : method.comments.entrySet()) {
				program.getListing().setComment(ent.getKey(), CodeUnit.PRE_COMMENT, ent.getValue());
			}
			try {
				program.getFunctionManager()
						.createFunction(SymbolUtilities.replaceInvalidChars(method.name, true),
							body.getMinAddress(), body,
							SourceType.IMPORTED);
			}
			catch (InvalidInputException | OverlappingFunctionException e) {
				log.appendMsg("Couldn't create function: " + method.name + ": " + e);
			}
			monitor.incrementProgress(1);
		}
	}

	void putMethod(JitMethod method, Program program) {
		if (method == null) {
			return;
		}
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		methods.add(method);
		for (ULongSpan span : method.bytes.getInitialized(0, -1).spans()) {
			fullSet.add(space.getAddress(span.min()), space.getAddress(span.max()));
		}
	}
}
