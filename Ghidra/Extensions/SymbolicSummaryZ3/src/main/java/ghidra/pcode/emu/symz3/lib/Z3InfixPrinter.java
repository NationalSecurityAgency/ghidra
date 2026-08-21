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
package ghidra.pcode.emu.symz3.lib;

import java.math.BigInteger;
import java.util.List;

import com.microsoft.z3.*;
import com.microsoft.z3.FuncDecl.Parameter;
import com.microsoft.z3.enumerations.Z3_decl_kind;

import ghidra.symz3.model.SymValueZ3;

@SuppressWarnings({ "rawtypes", "unchecked" })
public class Z3InfixPrinter {
	private static final boolean SHOW_ALL_SIZES = true;
	private static final boolean FORCE_UNSIGNED = false; //any numeric values will display as unsigned values

	private final Context ctx;

	public Z3InfixPrinter(Context ctx) {
		this.ctx = ctx;
	}

	public String symbolForZ3(Z3_decl_kind op) {
		return switch (op) {
			case Z3_decl_kind.Z3_OP_EQ -> "==";
			case Z3_decl_kind.Z3_OP_BMUL -> "*";
			case Z3_decl_kind.Z3_OP_BADD -> "+";
			case Z3_decl_kind.Z3_OP_BSUB -> "-";
			case Z3_decl_kind.Z3_OP_SLEQ -> "<=";
			case Z3_decl_kind.Z3_OP_NOT -> "not";
			case Z3_decl_kind.Z3_OP_AND -> "&&";
			case Z3_decl_kind.Z3_OP_OR -> "||";
			case Z3_decl_kind.Z3_OP_CONCAT -> "::";
			case Z3_decl_kind.Z3_OP_ULEQ -> "u<=";
			case Z3_decl_kind.Z3_OP_BAND -> "&";
			case Z3_decl_kind.Z3_OP_BOR -> "|";
			default -> op.toString();
		};
	}

	public Expr printSimplificationsConcat(Expr e) {
		//Msg.debug(this, "Print simplification of " + e);
		if (e.getNumArgs() == 2) {
			// check if the first argument is 0, if so we omit as it is implied
			Expr arg0 = e.getArgs()[0];
			if (arg0.isNumeral()) {
				BitVecNum bvn = (BitVecNum) arg0;
				if (bvn.getInt() == 0) {
					return e.getArgs()[1];
				}
			}

		}
		else if (e.getNumArgs() > 2) {
			Expr arg0 = e.getArgs()[0];
			if (arg0.isNumeral()) {
				BitVecNum bvn = (BitVecNum) arg0;
				if (bvn.getInt() == 0) {
					Expr result = ctx.mkConcat(e.getArgs()[1], e.getArgs()[2]);
					for (int i = 0; i < e.getNumArgs() - 3; i++) {
						result = ctx.mkConcat(result, e.getArgs()[i + 3]);
					}
					return result;
				}
			}
		}
		return e;
	}

	public Expr normalize(Expr e) {
		// precondition is that the op is commutative
		if (e.getNumArgs() == 2) {
			Expr arg0 = e.getArgs()[0];
			Expr arg1 = e.getArgs()[1];
			if (arg0.isNumeral() && !arg1.isNumeral()) {
				Expr[] swap = { arg1, arg0 };
				return e.update(swap);
			}
		}
		return e;
	}

	public Expr printSimplifications(Expr e) {
		Z3_decl_kind op = e.getFuncDecl().getDeclKind();
		if (op == Z3_decl_kind.Z3_OP_CONCAT) {
			return printSimplificationsConcat(e);
		}
		return e;
	}

	public String infix(Expr e) {
		return infixHelper(e, '(', ')', SHOW_ALL_SIZES, FORCE_UNSIGNED);
	}

	public String infixForceSize(Expr e) {
		return infixHelper(e, '(', ')', true, FORCE_UNSIGNED);
	}

	public String infixWithBrackets(Expr e) {
		return infixHelper(e, '[', ']', SHOW_ALL_SIZES, FORCE_UNSIGNED);
	}

	public String infixTopLevel(Expr e) {
		return infixHelper(e, ' ', ' ', SHOW_ALL_SIZES, FORCE_UNSIGNED);
	}

	public String uninterpretedStringHelper(Expr e) {
		String name = e.getFuncDecl().getName().toString();
		if (e.getNumArgs() == 0)
			return name;
		if (e.getNumArgs() != 1)
			return e.toString();
		if (name.equals("load_64_8") || name.equals("load_64_16") || name.equals("load_64_32") ||
			name.equals("load_64_64")) {
			BitVecExpr eb = (BitVecExpr) e;
			int bitSize = eb.getSortSize();
			String result =
				"MEM" + infixWithBrackets(e.getArgs()[0]) + ":" + Integer.toString(bitSize);
			//println("uninterpreted helper given " + e + " will return " + result);
			return result;

		}
		return "(print helper needed)" + e.toString();
	}

	public class RegisterPlusConstant {
		public String registerName;
		public BigInteger constant;
		public boolean isNegative;

		public RegisterPlusConstant(String name, BigInteger c, boolean isneg) {
			this.registerName = name;
			this.constant = c;
			this.isNegative = isneg;
		}
	}

	// if the BitVecExpr eb represents a negative number, return the magnitue of that number else null
	// e.g., "-6" we return 6.
	public BigInteger isNegativeConstant(BitVecExpr eb) {

		if (!eb.isNumeral()) {
			//Msg.info(this, "no, " + eb.getSExpr() + " is not negative its not even a number");
			return null;
		}

		BitVecNum ebnum = (BitVecNum) eb;
		String ebstring = ebnum.toBinaryString();

		// when converted by Z3, leading zeroes are removed!  So what we do is check the size of the
		// string versus the sort size.  Previously we used extract but there is some sort of Z3 issue...

		if (ebstring.length() < eb.getSortSize() || ebstring.length() == 1) {
			//Msg.info(this, "no, " + eb.getSExpr() + " is not negative as the sign bit is not a 1");
			return null;
		}

		assert (ebstring.charAt(0) == '1');
		ebstring = ebstring.replace('1', 'F');
		ebstring = ebstring.replace('0', '1');
		ebstring = ebstring.replace('F', '0');
		BigInteger bi = new BigInteger(ebstring, 2);
		bi = bi.add(BigInteger.ONE);

		//Msg.info(this, "yes, " + eb.getSExpr() + " is negative " + bi);
		return bi;

	}

	public BigInteger isConstant(BitVecExpr eb) {
		if (!eb.isNumeral()) {
			return null;
		}
		BitVecNum num = (BitVecNum) eb;
		return num.getBigInteger();
	}

	public boolean isCommutative(Z3_decl_kind op) {
		return (op == Z3_decl_kind.Z3_OP_BADD ||
			op == Z3_decl_kind.Z3_OP_BMUL ||
			op == Z3_decl_kind.Z3_OP_BOR ||
			op == Z3_decl_kind.Z3_OP_BAND);
	}

	public boolean isSizeForcing(Z3_decl_kind op) {
		return (op == Z3_decl_kind.Z3_OP_CONCAT ||
			op == Z3_decl_kind.Z3_OP_BOR ||
			op == Z3_decl_kind.Z3_OP_BAND);
	}

	public String infixHelper(Expr e, boolean forceSize) {
		return infixHelper(e, '(', ')', forceSize, FORCE_UNSIGNED);
	}

	public String infixUnsigned(Expr e) {
		return infixHelper(e, '(', ')', SHOW_ALL_SIZES, true);
	}

	@SuppressWarnings("unused")
	public String infixHelper(Expr e, char lchr, char rchr, boolean forceSize,
			boolean forceUnsigned) {
		if (e == null) {
			return "null";
		}
		Z3_decl_kind op = e.getFuncDecl().getDeclKind();

		// print_simplifications breaks the invariant that sizes of things on the right and left are equal
		if (!forceSize) {
			//e = print_simplifications(e);
		}

		if (isCommutative(op)) {
			e = normalize(e);
		}

		if (op == Z3_decl_kind.Z3_OP_UNINTERPRETED) {
			String result = uninterpretedStringHelper(e);
			if (lchr == '[') {
				return lchr + result + rchr;
			}
			return result;
		}

		if (op == Z3_decl_kind.Z3_OP_EXTRACT) {
			Parameter[] params = e.getFuncDecl().getParameters();
			// This is more Sleigh-opinionated....
			return "%s[%d:%d]".formatted(
				infixForceSize(e.getArgs()[0]),
				params[1].getInt(),
				params[0].getInt() - params[1].getInt() + 1);
			/*return "extract(" + infixForceSize(e.getArgs()[0]) + "," + params[0].getInt() + "," +
				params[1].getInt() + ")";*/
		}

		if (op == Z3_decl_kind.Z3_OP_ITE) {
			Parameter[] params = e.getFuncDecl().getParameters();
			return "%s ? %s : %s".formatted(
				infixForceSize(e.getArgs()[0]),
				infixForceSize(e.getArgs()[1]),
				infixForceSize(e.getArgs()[2]));
		}

		// problem here... the helper might transform our expression.
		String opString = symbolForZ3(op);
		if (e.getNumArgs() >= 2) {
			String result = infixHelper(e.getArgs()[0],
				SHOW_ALL_SIZES || (isSizeForcing(op) && e.getArgs()[0].isNumeral()));

			for (int i = 1; i < e.getNumArgs(); i++) {
				result = result + " " + opString + " ";
				result = result + infixHelper(e.getArgs()[i],
					SHOW_ALL_SIZES || (isSizeForcing(op) && e.getArgs()[i].isNumeral()));
			}

			return lchr + result + rchr;
		}
		if (e.getNumArgs() == 1) {
			Expr arg0 = e.getArgs()[0];
			return opString + lchr + infix(arg0) + rchr;
		}
		if (e.getNumArgs() == 0) {
			if (e.isBV()) {
				BitVecExpr eb = (BitVecExpr) e;
				String sizeString = "";
				if (SHOW_ALL_SIZES || forceSize) {
					sizeString = ":" + eb.getSortSize();
				}
				if (e.isNumeral()) {
					BitVecNum bvn = (BitVecNum) e;
					if (forceUnsigned) {
						return lchr + "0x" + bvn.getBigInteger().toString(16) + sizeString + rchr;
					}
					BigInteger b = isNegativeConstant(eb);
					if (b == null) {
						BigInteger bi = bvn.getBigInteger();
						return lchr + "0x" + bi.toString(16) + sizeString + rchr;
					}
					return lchr + "-0x" + b.toString(16) + sizeString + rchr;
				}
				return eb.toString() + sizeString;
			}
			return e.toString();
		}
		return "multi-arg" + " for " + op + "yields: " + e.toString();
	}

	public String fetchListOfStringsHelper(List<String> elements) {
		StringBuilder result = new StringBuilder();
		boolean comma = false;
		for (String r : elements) {
			if (comma) {
				result.append(", ");
			}
			result.append(r);
			comma = true;
		}
		result.append(System.lineSeparator());
		return result.toString();
	}

	public String infix(SymValueZ3 value) {
		if (value.getBoolExpr(ctx) != null) {
			return infix(value.getBoolExpr(ctx));
		}
		return infix(value.getBitVecExpr(ctx));
	}

	public String infixWithSexpr(SymValueZ3 value) {
		Expr e = value.hasBoolExpr() ? value.getBoolExpr(ctx) : value.getBitVecExpr(ctx);
		return infix(value) + " internal sexpr: " + e.toString();
	}
}
