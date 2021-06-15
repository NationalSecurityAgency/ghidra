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
package ghidra.dbg.target;

import java.io.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * An interface which indicates this object is capable of launching targets
 * 
 * <p>
 * The targets this launcher creates ought to appear in its successors.
 */
@DebuggerTargetObjectIface("Launcher")
public interface TargetLauncher extends TargetObject {

	/**
	 * An interface which provides default implementations for command-line launchers
	 * 
	 * <p>
	 * This interface should only be used by implementors. It is not necessarily marshalled by
	 * remote clients. Clients should instead interrogate {@link TargetLauncher} for its supported
	 * parameters.
	 * 
	 * <p>
	 * For the sake of parameter marshalling, the implementation must still set
	 * {@link TargetMethod#PARAMETERS_ATTRIBUTE_NAME} explicitly, usually in its constructor.
	 */
	interface TargetCmdLineLauncher extends TargetLauncher {
		String CMDLINE_ARGS_NAME = "args";

		/**
		 * The {@code args} parameter
		 */
		ParameterDescription<String> PARAMETER_CMDLINE_ARGS = ParameterDescription.create(
			String.class,
			CMDLINE_ARGS_NAME, true, "", "Command Line", "space-separated command-line arguments");

		/**
		 * A map of parameters suitable for invoking {@link #launch(List)}
		 */
		TargetParameterMap PARAMETERS = TargetMethod.makeParameters(PARAMETER_CMDLINE_ARGS);

		@Override
		default public TargetParameterMap getParameters() {
			return PARAMETERS;
		}

		/**
		 * Launch a target using the given arguments
		 * 
		 * <p>
		 * This is mostly applicable to user-space contexts, in which case, this usually means to
		 * launch a new process with the given arguments, where the first argument is the path to
		 * the executable image on the target host's file system.
		 * 
		 * @param args the arguments
		 * @return a future which completes when the command has been processed
		 */
		public CompletableFuture<Void> launch(List<String> args);

		/**
		 * @see #launch(List)
		 */
		public default CompletableFuture<Void> launch(String... args) {
			return launch(Arrays.asList(args));
		}

		@Override
		public default CompletableFuture<Void> launch(Map<String, ?> args) {
			return launch(CmdLineParser.tokenize(PARAMETER_CMDLINE_ARGS.get(args)));
		}
	}

	class CmdLineParser extends StreamTokenizer {
		public static List<String> tokenize(String cmdLine) {
			return new CmdLineParser(cmdLine).tokens();
		}

		public CmdLineParser(Reader r) {
			super(r);
			resetSyntax();
			wordChars(0, 255);
			whitespaceChars(' ', ' ');
			quoteChar('"');
		}

		public CmdLineParser(String cmdLine) {
			this(new StringReader(cmdLine));
		}

		public List<String> tokens() {
			List<String> list = new ArrayList<>();

			try {
				while (StreamTokenizer.TT_EOF != nextToken()) {
					list.add(sval);
				}
			}
			catch (IOException e) {
				throw new AssertionError(e);
			}

			return list;
		}
	}

	@TargetAttributeType(
		name = TargetMethod.PARAMETERS_ATTRIBUTE_NAME,
		required = true,
		hidden = true)
	default public TargetParameterMap getParameters() {
		return TargetMethod.getParameters(this);
	}

	/**
	 * Launch a target using the given arguments
	 * 
	 * @param args the map of arguments.
	 * @return a future which completes when the command is completed
	 */
	public CompletableFuture<Void> launch(Map<String, ?> args);
}
