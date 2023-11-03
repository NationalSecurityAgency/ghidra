/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.assembler.sleigh;

import java.util.Optional;

import ghidra.program.model.address.Address;

public interface WildcardMetadata {
	public Address getAnticipatedAddress();
	public int getInstanceId();
	public String getName();
	public Optional<String> getInitiator();
}
