/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.provider.relatedMatches;

import ghidra.feature.vt.api.main.VTAssociationStatus;

public enum VTRelatedMatchType {
	TARGET_MATCHES_TARGET_ACCEPTED(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.ACCEPTED,
			100),

	CALLER_MATCHES_CALLER_ACCEPTED(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.ACCEPTED,
			90), CALLEE_MATCHES_CALLEE_ACCEPTED(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.ACCEPTED,
			90),

	TARGET_MATCHES_TARGET_AVAILABLE(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.AVAILABLE,
			80),

	CALLER_MATCHES_CALLER_AVAILABLE(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.AVAILABLE,
			80), CALLEE_MATCHES_CALLEE_AVAILABLE(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.AVAILABLE,
			80),

	CALLER_MATCHES_TARGET_LOCKED_OUT(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.BLOCKED,
			70), CALLEE_MATCHES_TARGET_LOCKED_OUT(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.BLOCKED,
			70), TARGET_MATCHES_CALLER_LOCKED_OUT(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.BLOCKED,
			70), TARGET_MATCHES_CALLEE_LOCKED_OUT(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.BLOCKED,
			70),

	TARGET_MATCHES_UNRELATED_LOCKED_OUT(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.UNRELATED,
			VTAssociationStatus.BLOCKED,
			70), UNRELATED_MATCHES_TARGET_LOCKED_OUT(VTRelatedMatchCorrelationType.UNRELATED,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.BLOCKED,
			70),

	CALLER_MATCHES_CALLEE_LOCKED_OUT(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.BLOCKED,
			60), CALLEE_MATCHES_CALLER_LOCKED_OUT(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.BLOCKED,
			60),

	CALLER_MATCHES_UNRELATED_LOCKED_OUT(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.UNRELATED,
			VTAssociationStatus.BLOCKED,
			60), CALLEE_MATCHES_UNRELATED_LOCKED_OUT(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.UNRELATED,
			VTAssociationStatus.BLOCKED,
			60), UNRELATED_MATCHES_CALLER_LOCKED_OUT(VTRelatedMatchCorrelationType.UNRELATED,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.BLOCKED,
			60), UNRELATED_MATCHES_CALLEE_LOCKED_OUT(VTRelatedMatchCorrelationType.UNRELATED,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.BLOCKED,
			60),

	CALLER_MATCHES_UNRELATED_AVAILABLE(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.UNRELATED,
			VTAssociationStatus.AVAILABLE,
			50), CALLEE_MATCHES_UNRELATED_AVAILABLE(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.UNRELATED,
			VTAssociationStatus.AVAILABLE,
			50), UNRELATED_MATCHES_CALLER_AVAILABLE(VTRelatedMatchCorrelationType.UNRELATED,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.AVAILABLE,
			50), UNRELATED_MATCHES_CALLEE_AVAILABLE(VTRelatedMatchCorrelationType.UNRELATED,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.AVAILABLE,
			50),

	TARGET_MATCHES_UNRELATED_AVAILABLE(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.UNRELATED,
			VTAssociationStatus.AVAILABLE,
			50), UNRELATED_MATCHES_TARGET_AVAILABLE(VTRelatedMatchCorrelationType.UNRELATED,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.AVAILABLE,
			50),

	CALLER_MATCHES_TARGET_AVAILABLE(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.AVAILABLE,
			50), CALLEE_MATCHES_TARGET_AVAILABLE(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.AVAILABLE,
			50), TARGET_MATCHES_CALLER_AVAILABLE(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.AVAILABLE,
			50), TARGET_MATCHES_CALLEE_AVAILABLE(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.AVAILABLE,
			50),

	CALLER_MATCHES_CALLEE_AVAILABLE(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.AVAILABLE,
			50), CALLEE_MATCHES_CALLER_AVAILABLE(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.AVAILABLE,
			50),

	CALLER_MATCHES_UNRELATED_ACCEPTED(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.UNRELATED,
			VTAssociationStatus.ACCEPTED,
			40), CALLEE_MATCHES_UNRELATED_ACCEPTED(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.UNRELATED,
			VTAssociationStatus.ACCEPTED,
			40), UNRELATED_MATCHES_CALLER_ACCEPTED(VTRelatedMatchCorrelationType.UNRELATED,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.ACCEPTED,
			40), UNRELATED_MATCHES_CALLEE_ACCEPTED(VTRelatedMatchCorrelationType.UNRELATED,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.ACCEPTED,
			40),

	CALLER_MATCHES_CALLER_LOCKED_OUT(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.BLOCKED,
			30), CALLEE_MATCHES_CALLEE_LOCKED_OUT(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.BLOCKED,
			30),

	CALLER_MATCHES_CALLEE_ACCEPTED(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.ACCEPTED,
			20), CALLEE_MATCHES_CALLER_ACCEPTED(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.ACCEPTED,
			20),

	TARGET_MATCHES_UNRELATED_ACCEPTED(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.UNRELATED,
			VTAssociationStatus.ACCEPTED,
			10), UNRELATED_MATCHES_TARGET_ACCEPTED(VTRelatedMatchCorrelationType.UNRELATED,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.ACCEPTED,
			10),

	CALLER_MATCHES_TARGET_ACCEPTED(VTRelatedMatchCorrelationType.CALLER,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.ACCEPTED,
			10), CALLEE_MATCHES_TARGET_ACCEPTED(VTRelatedMatchCorrelationType.CALLEE,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.ACCEPTED,
			10), TARGET_MATCHES_CALLER_ACCEPTED(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.CALLER,
			VTAssociationStatus.ACCEPTED,
			10), TARGET_MATCHES_CALLEE_ACCEPTED(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.CALLEE,
			VTAssociationStatus.ACCEPTED,
			10),

	TARGET_MATCHES_TARGET_LOCKED_OUT(VTRelatedMatchCorrelationType.TARGET,
			VTRelatedMatchCorrelationType.TARGET,
			VTAssociationStatus.BLOCKED,
			0), ;

	public static VTRelatedMatchType findMatchType(VTRelatedMatchCorrelationType sourceType,
			VTRelatedMatchCorrelationType destinationType, VTAssociationStatus associationStatus) {
		VTRelatedMatchType[] values = VTRelatedMatchType.values();
		for (VTRelatedMatchType relatedMatchType : values) {
			if (relatedMatchType.sourceType == sourceType &&
				relatedMatchType.destinationType == destinationType &&
				relatedMatchType.associationStatus == associationStatus) {
				return relatedMatchType;
			}
		}
		return null;
	}

	public VTRelatedMatchCorrelationType getSourceType() {
		return sourceType;
	}

	public VTRelatedMatchCorrelationType getDestinationType() {
		return destinationType;
	}

	public VTAssociationStatus getAssociationStatus() {
		return associationStatus;
	}

	public int getGoodness() {
		return goodness;
	}

	private final VTRelatedMatchCorrelationType sourceType;
	private final VTRelatedMatchCorrelationType destinationType;
	private final VTAssociationStatus associationStatus;
	private final int goodness;

	private VTRelatedMatchType(VTRelatedMatchCorrelationType sourceType,
			VTRelatedMatchCorrelationType destinationType, VTAssociationStatus associationStatus,
			int goodness) {
		this.goodness = goodness;
		this.sourceType = sourceType;
		this.destinationType = destinationType;
		this.associationStatus = associationStatus;
	}
}
