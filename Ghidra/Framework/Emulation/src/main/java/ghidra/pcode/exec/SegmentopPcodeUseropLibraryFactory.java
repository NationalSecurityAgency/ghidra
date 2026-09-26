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
package ghidra.pcode.exec;

import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropSymbolMap;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A factory for the userops declared by {@code <segmentop>} tags in a processor spec
 *
 * <p>
 * Each userop executes the p-code body of its {@code <segmentop>}, so the emulator computes the
 * same address the decompiler does. Languages without a {@code <segmentop>} get an empty library.
 * Processor libraries are applied after this one, so they can still override a segment userop.
 */
@UseropLibrary(id = "segmentop", includeAlways = true, order = 0)
public class SegmentopPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	/** The suffix {@link InjectPayloadSegment} appends to the userop name */
	private static final String PAYLOAD_SUFFIX = "_pcode";

	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new SegmentopPcodeUseropLibrary<>(language);
	}

	/**
	 * The library of segment userops for one language
	 *
	 * @param <T> the type of values in the emulator
	 */
	public static class SegmentopPcodeUseropLibrary<T> extends DefaultPcodeUseropLibrary<T> {
		public SegmentopPcodeUseropLibrary(SleighLanguage language) {
			List<InjectPayloadSleigh> declared = language.getAdditionalInject();
			if (declared == null) {
				return;
			}
			// The compiler spec's inject library holds the compiled form of each payload
			PcodeInjectLibrary injectLibrary =
				language.getDefaultCompilerSpec().getPcodeInjectLibrary();
			for (InjectPayloadSleigh payload : declared) {
				if (!(payload instanceof InjectPayloadSegment)) {
					continue;
				}
				String payloadName = payload.getName();
				InjectPayload compiled =
					injectLibrary.getPayload(InjectPayload.EXECUTABLEPCODE_TYPE, payloadName);
				if (compiled == null) {
					continue;
				}
				String name = payloadName.endsWith(PAYLOAD_SUFFIX)
						? payloadName.substring(0, payloadName.length() - PAYLOAD_SUFFIX.length())
						: payloadName;
				putOp(new SegmentopPcodeUseropDefinition<>(language, name, compiled));
			}
		}
	}

	/**
	 * A userop that executes the p-code of a {@code <segmentop>} payload
	 *
	 * <p>
	 * The payload is instantiated once for each combination of argument varnodes. Its temporaries
	 * are allocated in the inject region of the unique space, so they cannot collide with those of
	 * the instruction invoking the userop.
	 *
	 * @param <T> the type of values in the emulator
	 */
	public static class SegmentopPcodeUseropDefinition<T> implements PcodeUseropDefinition<T> {
		private final SleighLanguage language;
		private final String name;
		private final InjectPayload payload;
		private final Address injectAddress;
		private final Map<List<Varnode>, PcodeProgram> cacheByArgs = new ConcurrentHashMap<>();

		public SegmentopPcodeUseropDefinition(SleighLanguage language, String name,
				InjectPayload payload) {
			this.language = language;
			this.name = name;
			this.payload = payload;
			this.injectAddress = language.getDefaultSpace().getAddress(0);
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public int getInputCount() {
			return payload.getInput().length;
		}

		@Override
		public void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library,
				PcodeOp op, Varnode outVar, List<Varnode> inVars) {
			List<Varnode> args = new ArrayList<>(inVars.size() + 1);
			args.add(outVar);
			args.addAll(inVars);
			executor.execute(cacheByArgs.computeIfAbsent(args, this::programFor), library);
		}

		private PcodeProgram programFor(List<Varnode> args) {
			InjectContext context = new InjectContext();
			context.language = language;
			context.baseAddr = injectAddress;
			context.nextAddr = injectAddress;
			context.inputlist = new ArrayList<>(args.subList(1, args.size()));
			context.output = args.get(0) == null
					? new ArrayList<>()
					: new ArrayList<>(List.of(args.get(0)));
			try {
				PcodeOp[] pcode = payload.getPcode(null, context);
				return new PcodeProgram(language, List.of(pcode),
					PcodeUseropSymbolMap.empty(language));
			}
			catch (Exception e) {
				throw new PcodeExecutionException(
					"Cannot instantiate segmentop '%s': %s".formatted(name, e.getMessage()), e);
			}
		}

		@Override
		public boolean isFunctional() {
			return false;
		}

		@Override
		public boolean canInterrupt() {
			return false;
		}

		@Override
		public boolean hasSideEffects() {
			return true;
		}

		@Override
		public boolean modifiesContext() {
			return false;
		}

		@Override
		public boolean canInlinePcode() {
			return true;
		}

		@Override
		public boolean isOutSigned() {
			return false;
		}

		@Override
		public boolean isInSigned(int index) {
			return false;
		}

		@Override
		public Class<?> getOutputType() {
			return null;
		}

		@Override
		public Method getJavaMethod() {
			return null;
		}

		@Override
		public PcodeUseropLibrary<?> getDefiningLibrary() {
			return null;
		}
	}
}
