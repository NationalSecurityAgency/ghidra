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
package ghidra.pcode.emu.symz3;

import java.io.PrintStream;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.tuple.Pair;

import com.microsoft.z3.Context;

import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.app.util.pcode.StringPcodeFormatter;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.pcode.emu.symz3.plain.SymZ3Space;
import ghidra.symz3.model.SymValueZ3;

public interface SymZ3PcodeEmulatorTrait
		extends PcodeMachine<Pair<byte[], SymValueZ3>>, SymZ3RecordsExecution {

	@Override
	SymZ3PcodeThread newThread();

	@Override
	SymZ3PcodeThread newThread(String name);

	@Override
	Collection<? extends SymZ3PcodeThread> getAllThreads();

	@Override
	SymZ3PairedPcodeExecutorState getSharedState();

	default AbstractSymZ3PcodeExecutorStatePiece<? extends SymZ3Space> getSharedSymbolicState() {
		return getSharedState().getRight();
	}

	@Override
	default List<RecInstruction> getInstructions() {
		return getSharedSymbolicState().getInstructions();
	}

	@Override
	default List<RecOp> getOps() {
		return getSharedSymbolicState().getOps();
	}

	default String printableSummary() {
		StringBuilder result = new StringBuilder();
		for (SymZ3PcodeThread thread : this.getAllThreads()) {
			result.append(thread.getLocalSymbolicState().printableSummary());
			result.append(System.lineSeparator());
		}
		result.append(getSharedSymbolicState().printableSummary());
		result.append(System.lineSeparator());
		return result.toString();
	}

	default void printSymbolicSummary(PrintStream out) {
		out.println(this.printableSummary());
	}

	default String formatOps() {
		List<RecOp> ops = getOps();
		StringPcodeFormatter formatter = new StringPcodeFormatter() {
			int i = 0;

			@Override
			protected FormatResult formatOpTemplate(ToStringAppender appender, OpTpl op) {
				appender.appendLabel("[%s] ".formatted(ops.get(i++).thread().getName()));
				return super.formatOpTemplate(appender, op);
			}
		};
		return formatter.formatOps(getLanguage(), ops.stream().map(RecOp::op).toList());
	}

	default void printOps(PrintStream out) {
		out.println(formatOps());
	}

	default String formatInstructions() {
		return getInstructions().stream()
				.map(RecInstruction::toString)
				.collect(Collectors.joining(System.lineSeparator()));
	}

	default void printInstructions(PrintStream out) {
		out.println(formatInstructions());
	}

	default void printCompleteSummary(PrintStream out) {
		out.println("Instructions emulated:");
		out.println("----------------------");
		printInstructions(out);
		out.println("");
		out.println("Pcode emulated:");
		out.println("---------------");
		printOps(out);
		out.println("");
		out.println("Summary:");
		printSymbolicSummary(out);
	}

	default Stream<String> streamPreconditions(Context ctx, Z3InfixPrinter z3p) {
		Stream<String> shared = getSharedState().getRight().streamPreconditions(ctx, z3p);
		Stream<String> locals = getAllThreads().stream()
				.flatMap(t -> t.getLocalSymbolicState().streamPreconditions(ctx, z3p));
		return Stream.concat(shared, locals);
	}

	default Stream<Entry<String, String>> streamValuations(Context ctx, Z3InfixPrinter z3p) {
		Stream<Entry<String, String>> shared =
			getSharedState().getRight().streamValuations(ctx, z3p);
		Stream<Entry<String, String>> locals = getAllThreads().stream()
				.flatMap(t -> t.getLocalSymbolicState().streamValuations(ctx, z3p));
		return Stream.concat(shared, locals);
	}
}
