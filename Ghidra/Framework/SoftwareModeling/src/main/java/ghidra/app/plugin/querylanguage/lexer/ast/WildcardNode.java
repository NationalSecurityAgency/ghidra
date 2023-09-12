/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.ast;

import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import ghidra.app.plugin.querylanguage.Defaults;

import ghidra.program.model.address.Address;

public class WildcardNode extends InstructionComponentNode {
	// TODO: write something less clunky
	private static final String PARSE_PATTERN = "((?<!\\\\)(?:\\\\\\\\)*/)";
	private static final String CATCH_ALL = "*";

	private final boolean hasManuallySetAnyContext;
	private final boolean hasAnyContext;
	private final boolean hasInitiator;
	private final boolean hasDelimiter;
	private final boolean hasLengthField;
	private final boolean isCatchAll;

	private final String name;
	private String initiator;
	private final Pattern delimiter;
	private final int operandIdx;
	private int completionSizeLimit;
	private int id;
	private final int wildcardInstanceId;

	private Address anticipatedAddress;

	private static String checkWildcardName(final String wildcard) {
		String[] wildcardArgs = wildcard.replace("`", "").split(PARSE_PATTERN);
		if (wildcardArgs.length == 0 || wildcardArgs[0].equals("")) {
			throw new RuntimeException("Variable name not provided for a wildcard.");
		}
		return wildcardArgs[0];
	}

	public WildcardNode(final String wildcard, final int operandIdx, final int wildcardInstanceId) {
		super(checkWildcardName(wildcard));

		this.operandIdx = operandIdx;
		this.wildcardInstanceId = wildcardInstanceId;

		final var trueWildcard = wildcard.replace("`", "");

		if (trueWildcard.equals(CATCH_ALL)) {
			// TODO: support this better.
			hasManuallySetAnyContext = hasAnyContext = hasInitiator = hasDelimiter = hasLengthField = false;
			initiator = null;
			delimiter = null;
			name = CATCH_ALL;
			isCatchAll = true;
			return;
		}

		isCatchAll = false;

		final var splits = trueWildcard.split(PARSE_PATTERN);

		hasManuallySetAnyContext = hasAnyContext = splits.length > 1;
		hasInitiator = splits.length >= 2;
		hasDelimiter = splits.length >= 3;
		hasLengthField = splits.length >= 4;

		name = splits[0];

		if (hasInitiator) {
			initiator = splits[1];
		} else {
			initiator = Defaults.DEFAULT_INITIATOR;
		}

		if (hasDelimiter) {
			delimiter = Pattern.compile(splits[2]);
		} else {
			delimiter = null;
		}

		if (hasLengthField) {
			completionSizeLimit = Integer.parseInt(splits[3]);
		} else {
			completionSizeLimit = Integer.MAX_VALUE;
		}

	}

	protected WildcardNode(final WildcardNode wildcardNode) {
		super(wildcardNode.name);

		this.hasManuallySetAnyContext = wildcardNode.hasManuallySetAnyContext;
		this.hasAnyContext = wildcardNode.hasAnyContext;
		this.hasInitiator = wildcardNode.hasInitiator;
		this.hasDelimiter = wildcardNode.hasDelimiter;
		this.name = wildcardNode.name;
		this.initiator = wildcardNode.initiator;
		this.delimiter = wildcardNode.delimiter;
		this.isCatchAll = wildcardNode.isCatchAll;
		this.hasLengthField = wildcardNode.hasLengthField;
		this.operandIdx = wildcardNode.operandIdx;
		this.wildcardInstanceId = wildcardNode.wildcardInstanceId;
	}

	public boolean isCatchAll() {
		return isCatchAll;
	}

	public boolean hasManuallySetAnyContext() {
		return hasManuallySetAnyContext;
	}

	public boolean hasInitiator() {
		return hasInitiator;
	}

	public boolean hasDelimiter() {
		return hasDelimiter;
	}

	public String getName() {
		return name;
	}

	public int getOperandIdx() {
		return operandIdx;
	}

	public Optional<String> getInitiator() {
		return Optional.ofNullable(initiator);
	}

	public void setInitiator(String initiator) {
		this.initiator = initiator;
	}

	public Optional<Pattern> getDelimiter() {
		return Optional.ofNullable(delimiter);
	}

	public void setId(final int id) {
		this.id = id;
	}

	public int getId() {
		return id;
	}

	public int getInstanceId() {
		return wildcardInstanceId;
	}

	@Override
	public boolean equals(final Object that) {
		if (this == that) {
			return true;
		}

		if (!(that instanceof WildcardNode)) {
			return false;
		}

		return getName().equals(((WildcardNode) that).getName());
	}

	@Override
	public int hashCode() {
		return Objects.hash(getName());
	}

	public int getCompletionSizeLimit() {
		return completionSizeLimit;
	}

	public void setCompletionSizeLimit(final int completionSizeLimit) {
		this.completionSizeLimit = completionSizeLimit;
	}

	@Override
	public String getInstructionText() {
		return name;
	}

	/*
	 * We can do a better job of ensuring that we're guessing good values for
	 * wildcards if we know the address of the instruction that Ghidra is going to
	 * try to compile our instruction at, so here we stash away that address into
	 * the wildcards for later use
	 */
	public void setAnticipatedAddress(Address a) {
		this.anticipatedAddress = a;
	}

	public Address getAnticipatedAddress() {
		return this.anticipatedAddress;
	}
}
