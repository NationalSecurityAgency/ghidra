/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.assembler.sleigh;

import java.util.Map;


public interface WildcardedInstruction {
	public Map<Integer, WildcardMetadata> getWildcardMap();
}
