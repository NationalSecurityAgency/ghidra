/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.tokenizer.api;

public interface ContinuedMatcher {
	boolean op(StringStream stream, int length);
}
