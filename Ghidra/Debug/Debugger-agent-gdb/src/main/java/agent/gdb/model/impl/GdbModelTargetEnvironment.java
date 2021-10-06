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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import ghidra.async.AsyncFence;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "Environment",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	})
public class GdbModelTargetEnvironment
		extends DefaultTargetObject<TargetObject, GdbModelTargetInferior>
		implements TargetEnvironment {
	public static final String NAME = "Environment";

	public static final String VISIBLE_ARCH_ATTRIBUTE_NAME = "arch";
	public static final String VISIBLE_OS_ATTRIBUTE_NAME = "os";
	public static final String VISIBLE_ENDIAN_ATTRIBUTE_NAME = "endian";

	protected final GdbModelImpl impl;

	protected String arch = "(unknown)";
	protected String os = "(unknown)";
	protected String endian = "(unknown)";

	public GdbModelTargetEnvironment(GdbModelTargetInferior inferior) {
		super(inferior.impl, inferior, NAME, "Environment");
		this.impl = inferior.impl;

		changeAttributes(List.of(), Map.of(
			DEBUGGER_ATTRIBUTE_NAME, impl.session.debugger,
			ARCH_ATTRIBUTE_NAME, arch,
			OS_ATTRIBUTE_NAME, os,
			ENDIAN_ATTRIBUTE_NAME, endian,
			VISIBLE_ARCH_ATTRIBUTE_NAME, arch,
			VISIBLE_OS_ATTRIBUTE_NAME, os,
			VISIBLE_ENDIAN_ATTRIBUTE_NAME, endian),
			"Initialized");
		refreshInternal();
	}

	protected CompletableFuture<Void> refreshArchitecture() {
		/**
		 * GDB/MI is less informative than I'd like here. If the architecture is unset (i.e.,
		 * "auto"), then using -gdb-show architecture gives no fields at all. If the user sets it to
		 * "auto", then it just says value="auto". Useless. The same issue applies to the
		 * =cmd-param-changed event. The console, while not readily machine consumable, provides the
		 * information I need. Unfortunately, when the "auto" architecture changes, there is no
		 * notification. The best I can do is refresh when an inferior is started. In 8.0, the auto
		 * architecture is actually updated on "file", but it doesn't really matter until the target
		 * is running, anyway.
		 */
		/**
		 * TODO: This assumes the relevant inferior is the current one, or that the current
		 * inferior's environment is the same as the one starting, which I think is Good Enough.
		 * Attempting to switch inferiors while something is starting is a no-go, anyway. If there
		 * is a known thread -- unlikely for an inferior that is just starting -- we could use the
		 * --thread parameter.
		 */
		return CompletableFuture.supplyAsync(() -> null).thenCompose(__ -> {
			return impl.gdb.consoleCapture("show architecture", CompletesWithRunning.CANNOT);
		}).thenAccept(out -> {
			String[] tokens = out.split("\\s+");
			String arch = tokens[tokens.length - 1].trim();
			while (arch.endsWith(".") || arch.endsWith(")") || arch.endsWith("\"")) {
				arch = arch.substring(0, arch.length() - 1);
			}
			while (arch.startsWith("\"")) {
				arch = arch.substring(1);
			}
			// e.g., The target architecture is set automatically (currently i386)
			// e.g., The target architecture is assumed to be i386
			// e.g., The target architecture is set to "auto" (currently "i386").
			// TODO: I don't have a way to detect if this parsing strategy fails.
			// TODO: I could search using a list of support architectures
			//       Use "set architecture" to get "Valid arguments"
			//       But, that may also be (perhaps more) version dependent
			this.arch = arch;
		}).exceptionally(e -> {
			model.reportError(this, "Could not get target architecture", e);
			return null;
		});
	}

	protected CompletableFuture<Void> refreshOS() {
		/**
		 * GDB/MI is similarly un-informative when os is "auto". See comments in
		 * refreshArchitecture.
		 */
		/**
		 * TODO: Ditto the "current inferior" issue as refreshArchitecture
		 */
		return CompletableFuture.supplyAsync(() -> null).thenCompose(__ -> {
			return impl.gdb.consoleCapture("show os", CompletesWithRunning.CANNOT);
		}).thenAccept(out -> {
			String[] tokens = out.split("\n")[0].split("\\s+");
			String os = tokens[tokens.length - 1].trim();
			if (os.endsWith(".")) {
				os = os.substring(0, os.length() - 1);
			}
			if (os.endsWith(")")) {
				os = os.substring(0, os.length() - 1);
			}
			if (os.startsWith("\"") && os.endsWith("\"")) {
				os = os.substring(1, os.length() - 1);
			}
			// e.g., The current OS ABI is "auto" (currently "GNU/Linux").
			// ...   The default OS ABI is "GNU/Linux".
			// e.g., The current OS ABI is "GNU/Linux".
			// TODO: I don't have a way to detect if this parsing strategy fails.
			// TODO: Use "set os" to get "Valid arguments"?
			//       Would need to ignore "auto", "default", and "none"?
			this.os = os;
		}).exceptionally(e -> {
			model.reportError(this, "Could not get target os", e);
			return null;
		});
	}

	protected CompletableFuture<Void> refreshEndian() {
		// TODO: This duplicates GdbInferiorImpl.syncEndianness....
		return CompletableFuture.supplyAsync(() -> null).thenCompose(__ -> {
			return impl.gdb.consoleCapture("show endian", CompletesWithRunning.CANNOT);
		}).thenAccept(out -> {
			if (out.toLowerCase().contains("little endian")) {
				endian = "little";
			}
			else if (out.toLowerCase().contains("big endian")) {
				endian = "big";
			}
			else {
				endian = "(unknown)";
			}
		}).exceptionally(e -> {
			model.reportError(this, "Could not get target endian", e);
			return null;
		});
	}

	protected CompletableFuture<Void> refreshInternal() {
		AsyncFence fence = new AsyncFence();
		fence.include(refreshArchitecture());
		fence.include(refreshOS());
		fence.include(refreshEndian());
		return fence.ready().thenAccept(__ -> {
			changeAttributes(List.of(), Map.of(
				ARCH_ATTRIBUTE_NAME, arch,
				OS_ATTRIBUTE_NAME, os,
				ENDIAN_ATTRIBUTE_NAME, endian,
				VISIBLE_ARCH_ATTRIBUTE_NAME, arch,
				VISIBLE_OS_ATTRIBUTE_NAME, os,
				VISIBLE_ENDIAN_ATTRIBUTE_NAME, endian //
			), "Refreshed");
		});
	}

	@TargetAttributeType(name = VISIBLE_ARCH_ATTRIBUTE_NAME)
	public String getVisibleArch() {
		return arch;
	}

	@TargetAttributeType(name = VISIBLE_OS_ATTRIBUTE_NAME)
	public String getVisibleOs() {
		return os;
	}

	@TargetAttributeType(name = VISIBLE_ENDIAN_ATTRIBUTE_NAME)
	public String getVisibleEndian() {
		return endian;
	}

	@Override
	public String getDebugger() {
		return impl.session.debugger;
	}

	@Override
	public String getArchitecture() {
		return arch;
	}

	@Override
	public String getOperatingSystem() {
		return os;
	}

	@Override
	public String getEndian() {
		return endian;
	}
}
