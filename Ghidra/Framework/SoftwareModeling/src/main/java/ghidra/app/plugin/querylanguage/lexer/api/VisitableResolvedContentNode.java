/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.lexer.api;

public interface VisitableResolvedContentNode {
	void accept(VisitableResolvedContentNodeVisitor visitor);
}
