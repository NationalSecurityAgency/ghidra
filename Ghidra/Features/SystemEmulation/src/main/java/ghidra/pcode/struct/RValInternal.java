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
package ghidra.pcode.struct;

import ghidra.pcode.struct.StructuredSleigh.LVal;
import ghidra.pcode.struct.StructuredSleigh.RVal;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;

interface RValInternal extends RVal {
	StructuredSleigh getContext();

	@Override
	DataType getType();

	StringTree generate(RValInternal parent);

	@Override
	default LVal deref() {
		return deref(getContext().language.getDefaultSpace());
	}

	@Override
	default LVal deref(AddressSpace space) {
		return new DerefExpr(getContext(), space, this);
	}

	@Override
	default RVal notb() {
		return new NotExpr(getContext(), this);
	}

	@Override
	default RVal noti() {
		return new InvExpr(getContext(), this);
	}

	@Override
	default RVal eq(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.EQ, rhs);
	}

	@Override
	default RVal eq(long rhs) {
		return eq(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal eqf(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.EQF, rhs);
	}

	@Override
	default RVal neq(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.NEQ, rhs);
	}

	@Override
	default RVal neq(long rhs) {
		return neq(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal neqf(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.NEQF, rhs);
	}

	@Override
	default RVal ltiu(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.LTIU, rhs);
	}

	@Override
	default RVal ltiu(long rhs) {
		return ltiu(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal ltis(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.LTIS, rhs);
	}

	@Override
	default RVal ltis(long rhs) {
		return ltis(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal ltf(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.LTF, rhs);
	}

	@Override
	default RVal gtiu(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.GTIU, rhs);
	}

	@Override
	default RVal gtiu(long rhs) {
		return gtiu(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal gtis(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.GTIS, rhs);
	}

	@Override
	default RVal gtis(long rhs) {
		return gtis(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal gtf(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.GTF, rhs);
	}

	@Override
	default RVal lteiu(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.LTEIU, rhs);
	}

	@Override
	default RVal lteiu(long rhs) {
		return lteiu(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal lteis(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.LTEIS, rhs);
	}

	@Override
	default RVal lteis(long rhs) {
		return lteis(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal ltef(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.LTEF, rhs);
	}

	@Override
	default RVal gteiu(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.GTEIU, rhs);
	}

	@Override
	default RVal gteiu(long rhs) {
		return gteiu(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal gteis(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.GTEIS, rhs);
	}

	@Override
	default RVal gteis(long rhs) {
		return gteis(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal gtef(RVal rhs) {
		return new CmpExpr(getContext(), this, CmpExpr.Op.GTEF, rhs);
	}

	@Override
	default RVal orb(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.ORB, rhs);
	}

	@Override
	default RVal orb(long rhs) {
		return orb(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal ori(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.ORI, rhs);
	}

	@Override
	default RVal ori(long rhs) {
		return ori(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal xorb(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.XORB, rhs);
	}

	@Override
	default RVal xorb(long rhs) {
		return xorb(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal xori(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.XORI, rhs);
	}

	@Override
	default RVal xori(long rhs) {
		return xori(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal andb(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.ANDB, rhs);
	}

	@Override
	default RVal andb(long rhs) {
		return andb(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal andi(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.ANDI, rhs);
	}

	@Override
	default RVal andi(long rhs) {
		return andi(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal shli(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.SHLI, rhs);
	}

	@Override
	default RVal shli(long rhs) {
		return shli(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal shriu(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.SHRIU, rhs);
	}

	@Override
	default RVal shriu(long rhs) {
		return shriu(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal shris(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.SHRIS, rhs);
	}

	@Override
	default RVal shris(long rhs) {
		return shris(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal addi(RVal rhs) {
		// TODO: Validate types? At least warn?
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.ADDI, rhs);
	}

	@Override
	default RVal addi(long rhs) {
		return addi(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal addf(RVal rhs) {
		// TODO: Validate types? At least warn?
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.ADDF, rhs);
	}

	@Override
	default RVal subi(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.SUBI, rhs);
	}

	@Override
	default RVal subi(long rhs) {
		return subi(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal subf(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.SUBF, rhs);
	}

	@Override
	default RVal muli(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.MULI, rhs);
	}

	@Override
	default RVal muli(long rhs) {
		return muli(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal mulf(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.MULF, rhs);
	}

	@Override
	default RVal diviu(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.DIVIU, rhs);
	}

	@Override
	default RVal diviu(long rhs) {
		return diviu(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal divis(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.DIVIS, rhs);
	}

	@Override
	default RVal divis(long rhs) {
		return divis(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal divf(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.DIVF, rhs);
	}

	@Override
	default RVal remiu(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.REMIU, rhs);
	}

	@Override
	default RVal remiu(long rhs) {
		return remiu(getContext().lit(rhs, getType().getLength()));
	}

	@Override
	default RVal remis(RVal rhs) {
		return new ArithBinExpr(getContext(), this, ArithBinExpr.Op.REMIS, rhs);
	}

	@Override
	default RVal remis(long rhs) {
		return remis(getContext().lit(rhs, getType().getLength()));
	}

}
