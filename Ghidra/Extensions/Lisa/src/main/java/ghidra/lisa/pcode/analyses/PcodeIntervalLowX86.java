/* ###
 * IP: MIT
 */
package ghidra.lisa.pcode.analyses;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.value.Identifier;
import it.unive.lisa.symbolic.value.Variable;
import it.unive.lisa.type.Untyped;
import it.unive.lisa.util.numeric.MathNumber;

/**
 * This class represents a pretty-extensive hack to enable low-pcode interval logic.  Low pcode differs from both source and high pcode
 * in that the calculations made to determine a branch are not co-located with the branch.  The information needed for the "assume"
 * processing (i.e. variables values assumed as a result fo the branch) is therefore not local.  The UpdateImpliedConditions is 
 * essentially a table match against the default X86 implementation of flag-lookups representing a particular branch condition.
 * 
 * 		JBE	CF || ZF
 * 		JB  CF  (unhandled)
 * 		JL  SF==OF 
 * 		JLE SF==OF || ZF
 * 
 */
public class PcodeIntervalLowX86 extends PcodeInterval {

	private class KeyPattern {

		// NB: At some point, we may want to convert this to a more generic type
		private String key;
		private PcodeInterval kinterval;

		public KeyPattern() {
			this.key = "";
		}

		public KeyPattern(String key) {
			this.key = key;
		}

		public void append(KeyPattern kp) {
			this.key += kp.key;
			if (this.kinterval == null) {
				this.kinterval = kp.kinterval;
			}
		}

		public void setKey(String key) {
			this.key = key;
		}

		public void setInterval(PcodeInterval interval) {
			if (this.kinterval == null) {
				this.kinterval = interval;
			}
		}

	}

	@Override
	protected ValueEnvironment<PcodeInterval> updateImpliedConditions(
			ValueEnvironment<PcodeInterval> environment,
			ProgramPoint src, ProgramPoint dest, PcodeInterval val, boolean complement) {
		KeyPattern key = buildKey(indexEnv(environment), val.target);
		LongInterval update = buildInterval(key, complement);
		if (update == null) {
			return environment;
		}
		PcodeOp tgt = key.kinterval.target;
		Varnode vn = key.kinterval.rightIsExpr ? tgt.getInput(0) : tgt.getInput(1);
		Identifier vnId =
			new Variable(Untyped.INSTANCE, vn.getAddress().toString(), dest.getLocation());
		PcodeInterval state = environment.getState(vnId);
		if (vn.isUnique()) {
			vnId = swapId(environment, dest, vnId, state);
		}
		PcodeInterval res = new PcodeInterval(update);
		res = intersection(res, state);
		return environment.putState(vnId, res);
	}

	private Map<String, PcodeInterval> indexEnv(ValueEnvironment<PcodeInterval> environment) {
		Map<String, PcodeInterval> map = new HashMap<>();
		for (Entry<Identifier, PcodeInterval> entry : environment) {
			map.put(entry.getKey().getName(), entry.getValue());
		}
		return map;
	}

	private KeyPattern buildKey(Map<String, PcodeInterval> envMap, PcodeOp op) {

		KeyPattern key = new KeyPattern();
		for (Varnode in : op.getInputs()) {
			String envKey = in.getAddress().toString();
			if (envMap.containsKey(envKey)) {
				PcodeInterval envVal = envMap.get(envKey);
				if (envVal.target != null) {
					key.append(buildKey(envMap, envVal.target));
				}
				else {
					Varnode out = op.getOutput();
					Address addr = out.getAddress();
					key = new KeyPattern(key.key + "(" + Long.toHexString(addr.getOffset()) + ")");
					if (isTerminal(op)) {
						key.setInterval(envMap.get(addr.toString()));
					}
					return key;
				}
			}
		}

		key.setKey(op.getMnemonic() + key.key);
		return key;
	}

	private boolean isTerminal(PcodeOp op) {
		Varnode out = op.getOutput();
		if (!out.isRegister()) {
			return false;
		}
		Address addr = out.getAddress();
		if ((addr.getOffset() & 0x200) == 0) {
			return false;
		}
		return (op.getInput(0).isRegister() || op.getInput(1).isRegister());
	}

	private String key2op(KeyPattern kp, boolean complement) {
		String ret = switch (kp.key) {
			case "BOOL_OR(206)INT_NOTEQUAL(20b)(207)", "BOOL_OR(206)INT_NOTEQUAL(207)(20b)" -> "JLE";
			case "BOOL_ANDBOOL_NEGATE(206)INT_EQUAL(20b)(207)", "BOOL_ANDBOOL_NEGATE(206)INT_EQUAL(207)(20b)" -> "JG";
			case "INT_NOTEQUAL(20b)(207)", "INT_NOTEQUAL(207)(20b)" -> "JL";
			case "INT_EQUAL(20b)(207)", "INT_EQUAL(207)(20b)" -> "JGE";
			case "BOOL_OR(200)(206)", "BOOL_OR(206)(200)" -> "JBE";
			case "BOOL_NEGATEBOOL_OR(200)(206)", "BOOL_NEGATEBOOL_OR(206)(200)" -> "JA";
			case "(200)" -> "JB";
			case "BOOL_NEGATE(200)" -> "JAE";
			default -> null;
		};
		if (ret == null) {
			return ret;
		}
		if (kp.kinterval != null && !kp.kinterval.rightIsExpr) {
			ret = ret.contains("A") ? ret.replace("A", "B") : ret.replace("B", "A");
			ret = ret.contains("G") ? ret.replace("G", "L") : ret.replace("L", "G");
		}
		if (complement) {
			ret = switch (ret) {
				case "JLE" -> "JG";
				case "JG" -> "JLE";
				case "JL" -> "JGE";
				case "JGE" -> "JL";
				case "JA" -> "JBE";
				case "JBE" -> "JA";
				case "JB" -> "JAE";
				case "JAE" -> "JB";
				default -> null;
			};
		}
		return ret;
	}

	private LongInterval buildInterval(KeyPattern key, boolean complement) {
		String comparison = key2op(key, complement);
		if (key.kinterval == null) {
			//Msg.error(this, "Null interval for key: " + key.key);
			return null;
		}
		MathNumber bnd = key.kinterval.bound;
		return switch (comparison) {
			case "JG" -> new LongInterval(bnd.add(MathNumber.ONE), MathNumber.PLUS_INFINITY);
			case "JLE" -> new LongInterval(MathNumber.MINUS_INFINITY, bnd);
			case "JGE" -> new LongInterval(bnd, MathNumber.PLUS_INFINITY);
			case "JL" -> new LongInterval(MathNumber.MINUS_INFINITY,
				bnd.subtract(MathNumber.ONE));
			case "JA" -> new LongInterval(bnd.add(MathNumber.ONE), MathNumber.PLUS_INFINITY);
			case "JBE" -> new LongInterval(MathNumber.MINUS_INFINITY, bnd);
			case "JAE" -> new LongInterval(bnd, MathNumber.PLUS_INFINITY);
			case "JB" -> new LongInterval(MathNumber.MINUS_INFINITY,
				bnd.subtract(MathNumber.ONE));
			default -> null;
		};
	}

	private Identifier swapId(ValueEnvironment<PcodeInterval> environment, ProgramPoint dest,
			Identifier vnId, PcodeInterval state) {
		for (Entry<Identifier, PcodeInterval> n : environment) {
			PcodeInterval v = n.getValue();
			if (v.interval.equals(state.interval) && !n.getKey().equals(vnId) &&
				n.getKey().toString().contains("register")) {
				vnId = new Variable(Untyped.INSTANCE, n.getKey().getName(),
					dest.getLocation());
				break;
			}
		}
		return vnId;
	}

	private PcodeInterval intersection(PcodeInterval a, PcodeInterval b) {
		if (a.interval.intersects(b.interval)) {
			MathNumber min = a.interval.getHigh().min(b.interval.getHigh());
			MathNumber max = a.interval.getLow().max(b.interval.getLow());
			return new PcodeInterval(min, max);
		}
		return bottom();
	}

}
