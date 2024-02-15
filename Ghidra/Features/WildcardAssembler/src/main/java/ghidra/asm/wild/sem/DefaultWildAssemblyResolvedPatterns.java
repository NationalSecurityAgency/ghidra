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
package ghidra.asm.wild.sem;

import java.util.*;

import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory.AbstractAssemblyResolutionBuilder;
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory.AbstractAssemblyResolvedPatternsBuilder;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.ContextOp;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.asm.wild.WildOperandInfo;
import ghidra.asm.wild.sem.WildAssemblyResolutionFactory.WildAssemblyResolvedPatternsBuilder;

public class DefaultWildAssemblyResolvedPatterns extends DefaultAssemblyResolvedPatterns
		implements WildAssemblyResolvedPatterns {

	protected final WildAssemblyResolutionFactory factory;
	protected final Set<WildOperandInfo> opInfo;

	protected DefaultWildAssemblyResolvedPatterns(WildAssemblyResolutionFactory factory,
			String description, Constructor cons, List<? extends AssemblyResolution> children,
			AssemblyResolution right, AssemblyPatternBlock ins, AssemblyPatternBlock ctx,
			Set<AssemblyResolvedBackfill> backfills, Set<AssemblyResolvedPatterns> forbids,
			Set<WildOperandInfo> opInfo) {
		super(factory, description, cons, children, right, ins, ctx, backfills, forbids);
		this.factory = factory;
		this.opInfo = opInfo == null ? Set.of() : Collections.unmodifiableSet(opInfo);
	}

	@Override
	public Set<WildOperandInfo> getOperandInfo() {
		return opInfo;
	}

	@Override
	protected int computeHash() {
		int result = super.computeHash();
		result *= 31;
		result += Objects.hashCode(opInfo);
		return result;
	}

	protected boolean wildPartsEqual(DefaultWildAssemblyResolvedPatterns that) {
		if (!partsEqual(that)) {
			return false;
		}
		if (!Objects.equals(this.opInfo, that.opInfo)) {
			return false;
		}
		return true;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		DefaultWildAssemblyResolvedPatterns that = (DefaultWildAssemblyResolvedPatterns) obj;
		return wildPartsEqual(that);
	}

	@Override
	public String lineToString() {
		return "WILD:" + super.lineToString();
	}

	@Override
	protected String childrenToString(String indent) {
		if (opInfo.isEmpty()) {
			return super.childrenToString(indent);
		}
		StringBuilder sb = new StringBuilder();
		sb.append(indent + "opInfo\n:");
		for (WildOperandInfo i : opInfo) {
			sb.append(indent + "  " + i + "\n");
		}
		sb.append(super.childrenToString(indent));
		return sb.toString();
	}

	protected WildAssemblyResolvedPatternsBuilder withWildInfoBuilder(String wildcard,
			List<AssemblyConstructorSemantic> path, AssemblyPatternBlock location,
			PatternExpression expression, Object choice) {
		var builder = factory.newPatternsBuilder();
		builder.copyFromDefault(this);
		var newOpInfo = new WildOperandInfo(wildcard, path, location, expression, choice);
		if (opInfo.isEmpty()) {
			builder.opInfo = Set.of(newOpInfo);
		} else {
			builder.opInfo = new HashSet<>(opInfo);
			builder.opInfo.add(newOpInfo);
		}
		return builder;
	}

	@Override
	public WildAssemblyResolvedPatterns withWildInfo(String wildcard,
			List<AssemblyConstructorSemantic> path, AssemblyPatternBlock location,
			PatternExpression expression, Object choice) {
		return withWildInfoBuilder(wildcard, path, location, expression, choice).build();
	}

	protected WildAssemblyResolvedPatterns cast(AssemblyResolvedPatterns pat) {
		return (WildAssemblyResolvedPatterns) pat;
	}

	protected WildAssemblyResolvedPatternsBuilder cast(
			AbstractAssemblyResolvedPatternsBuilder<?> builder) {
		return (WildAssemblyResolvedPatternsBuilder) builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder shiftBuilder(int amt) {
		var builder = cast(super.shiftBuilder(amt));
		builder.opInfo = new HashSet<>();
		for (WildOperandInfo info : opInfo) {
			builder.opInfo.add(info.shift(amt));
		}
		return builder;
	}

	// NOTE: Do not override truncateBuilder. The docs say only used for reading a context op.

	@Override
	protected AbstractAssemblyResolutionBuilder<?, ?> checkNotForbiddenBuilder() {
		var builder = super.checkNotForbiddenBuilder();
		if (builder instanceof WildAssemblyResolvedPatternsBuilder pb) {
			pb.opInfo = opInfo;
		}
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder combineBuilder(AssemblyResolvedPatterns pat) {
		var builder = cast(super.combineBuilder(pat));
		if (builder != null) {
			builder.opInfo = new HashSet<>(this.opInfo);
			builder.opInfo.addAll(cast(pat).getOperandInfo());
		}
		return builder;
	}

	// NOTE: Do not override combineLessBackfill. Taken care of by combineBuilder.

	@Override
	protected WildAssemblyResolvedPatternsBuilder combineBuilder(AssemblyResolvedBackfill bf) {
		var builder = cast(super.combineBuilder(bf));
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder withForbidsBuilder(
			Set<AssemblyResolvedPatterns> more) {
		var builder = cast(super.withForbidsBuilder(more));
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder withDescriptionBuilder(String description) {
		var builder = cast(super.withDescriptionBuilder(description));
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder withConstructorBuilder(Constructor cons) {
		var builder = cast(super.withConstructorBuilder(cons));
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder writeContextOpBuilder(ContextOp cop,
			MaskedLong val) {
		var builder = cast(super.writeContextOpBuilder(cop, val));
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder copyAppendDescriptionBuilder(String append) {
		var builder = cast(super.copyAppendDescriptionBuilder(append));
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder withRightBuilder(AssemblyResolution right) {
		var builder = cast(super.withRightBuilder(right));
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder nopLeftSiblingBuilder() {
		var builder = cast(super.nopLeftSiblingBuilder());
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder parentBuilder(String description, int opCount) {
		var builder = cast(super.parentBuilder(description, opCount));
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder maskOutBuilder(ContextOp cop) {
		var builder = cast(super.maskOutBuilder(cop));
		builder.opInfo = opInfo;
		return builder;
	}

	@Override
	protected WildAssemblyResolvedPatternsBuilder solveContextChangesForForbidsBuilder(
			AssemblyConstructorSemantic sem, Map<String, Long> vals) {
		var builder = cast(super.solveContextChangesForForbidsBuilder(sem, vals));
		builder.opInfo = opInfo;
		return builder;
	}
}
