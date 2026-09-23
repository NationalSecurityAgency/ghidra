// This file will eventually be incorporate upstream in the CTADL project.
// It resides here purely to facilitate coordination.

use ascent::ascent;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

// ==========================================
// 1. DOMAIN SPECIFIC TYPE ALIASES
// ==========================================
type PCodeInstruction = String;
type PCodeHighFunc = String;
type PCodeHighPrototype = String;
type PCodeBlockBasic = String;
type PCodeType = String;
type PCodeHighSymbol = String;
type PCodeHighVar = String;
type PCodeGenericCallingConvention = String;


// ==========================================
// 2. THE ASCENT DATALOG ENGINE BLOCK
// ==========================================
ascent! {
    // --- INPUT & UTILITY SCHEMAS ---
    relation pcode_id(PCodeInstruction, String);
    relation vnode_id(String, String);
    relation varnode_hfunc(String, PCodeHighFunc);
    relation varnode_hvar(String, String);
    relation op_hfunc(String, PCodeHighFunc);
    relation bb_hfunc(String, PCodeHighFunc);
    relation location_hfunc(String, PCodeHighFunc);
    relation tmp(String, String);

    relation HFUNC_FUNCX(PCodeHighFunc, String);
    relation HFUNC_NAMEX(PCodeHighFunc, String);
    relation HFUNC_ISEXTX(PCodeHighFunc);
    relation HFUNC_PROTOX(PCodeHighFunc, PCodeHighPrototype);
    relation HFUNC_EPX(PCodeHighFunc, String);
    relation HFUNC_LOCAL_EPX(String, String);

    relation BB_EDGE(PCodeBlockBasic, PCodeBlockBasic);
    relation BB_FIRSTX(PCodeBlockBasic, PCodeInstruction);
    relation BB_HFUNCX(PCodeBlockBasic, PCodeHighFunc);

    relation hvar_hfunc(String, String);
    relation HVAR_NAMEX(String, String);
    relation HVAR_TYPEX(String, PCodeType);
    relation HVAR_REPRESENTATIVEX(String, String);

    relation PCODE_MNEMONICX(PCodeInstruction, String);
    relation PCODE_PARENTX(PCodeInstruction, PCodeBlockBasic);
    relation PCODE_TARGETX(PCodeInstruction, String);
    relation PCODE_INPUTX(PCodeInstruction, usize, String);
    relation PCODE_OUTPUTX(PCodeInstruction, String);
    relation PCODE_OPCODEX(PCodeInstruction, String);
    relation PCODE_NEXTX(PCodeInstruction, PCodeInstruction);
    relation PCODE_INDEXX(PCodeInstruction, usize);

    relation VNODE_ADDRESSX(String, String);
    relation VNODE_PC_ADDRESSX(String, String);
    relation VNODE_OFFSETX(String, String);
    relation VNODE_OFFSET_NX(String, String);
    relation VNODE_SIZEX(String, usize);
    relation VNODE_SPACEX(String, String);
    relation VNODE_HVARX(String, String);
    relation VNODE_HFUNCX(String, PCodeHighFunc);
    relation VNODE_NAMEX(String, String);

    relation OFFSET_INDEXX(String, usize);

    relation PROTO_IS_CONSTRUCTORX(PCodeHighPrototype);
    relation PROTO_IS_DESTRUCTORX(PCodeHighPrototype);
    relation PROTO_IS_VARARGX(PCodeHighPrototype);
    relation PROTO_IS_INLINEX(PCodeHighPrototype);
    relation PROTO_IS_VOIDX(PCodeHighPrototype);
    relation PROTO_HAS_THISX(PCodeHighPrototype);
    relation PROTO_CALLING_CONVENTIONX(PCodeHighPrototype, PCodeGenericCallingConvention);
    relation PROTO_RETTYPEX(PCodeHighPrototype, String);
    relation PROTO_PARAMETERX(PCodeHighPrototype, usize, PCodeHighSymbol);
    relation PROTO_PARAMETER_COUNTX(PCodeHighPrototype, usize);
    relation PROTO_PARAMETER_DATATYPEX(PCodeHighSymbol, String);

    relation SYMBOL_HVARX(PCodeHighSymbol, PCodeHighVar);
    relation SYMBOL_HFUNCX(PCodeHighSymbol, PCodeHighFunc);
    relation SYMBOL_NAMEX(PCodeHighSymbol, String);

    relation LOCATION_NUM(String, String);
    relation LOCATION_HEX(String, String);
    relation LOCATION_FUNC(String, PCodeHighFunc);
    relation LOCATION_UNIQ(String, usize);
    relation MNEMONICS(String, String);
    relation VARIABLE_FIELD(String, String);

    relation FUNC_ISEXT(PCodeHighFunc);
    relation FUNC_PARAMETER(PCodeHighFunc, usize, PCodeHighSymbol);
    relation FUNC_PARAMETER_COUNT(PCodeHighFunc, usize);
    relation FUNC_PARAMETER_DATATYPE(PCodeHighSymbol, usize, String);

    relation A_ADDR_REF(String, usize);
    relation A_ADDR_SIZE(String, usize);
    relation A_ADDR_OFFSET(String, String);
    relation A_ADDR_SPACE(String, String);

    relation E_AST_BLOCK(String, PCodeBlockBasic);
    relation E_AST_VARNODES(String, String);

    relation A_BLOCK_INDEX(PCodeBlockBasic, usize);
    relation E_BLOCK_BLOCK(PCodeBlockBasic, PCodeBlockBasic);
    relation E_BLOCK_OP(PCodeBlockBasic, PCodeInstruction);
    relation E_BLOCK_RANGELIST(PCodeBlockBasic, String);
    relation E_BLOCK_STATEMENT(PCodeBlockBasic, String);
    relation E_BLOCK_VARIABLE(PCodeBlockBasic, String);

    relation A_BLOCKEDGE_INDEX(String, usize);
    relation E_BLOCKEDGE_EDGE(String, String);

    relation E_DOC_FUNCTION(PCodeHighFunc, String);

    relation A_EDGE_END(String, usize);

    relation A_FIELD_XMLCONTENT(String, String);

    relation E_FUNCTION_ADDR(String, String);
    relation E_FUNCTION_AST(String, String);
    relation E_FUNCTION_BLOCK(String, PCodeBlockBasic);
    relation E_FUNCTION_FUNCPROTO(String, PCodeHighPrototype);
    relation E_FUNCTION_HIGHLIST(String, String);
    relation E_FUNCTION_LOCALDB(String, String);
    relation A_FUNCTION_NAME(String, String);
    relation E_FUNCTION_VARDECL(String, String);

    relation E_FUNCPROTO_VARDECL(PCodeHighPrototype, String);

    relation E_HIGH_ADDR(PCodeHighVar, String);
    relation A_HIGH_CLASS(PCodeHighVar, String);
    relation A_HIGH_REPREF(PCodeHighVar, usize);
    relation A_HIGH_SYMREF(PCodeHighVar, usize);
    relation E_HIGH_TYPE(PCodeHighVar, PCodeType);
    relation E_HIGH_TYPEREF(PCodeHighVar, PCodeType);

    relation E_HIGHLIST_HIGH(String, PCodeHighVar);

    relation A_IOP_VALUE(String, String);

    relation A_INPUT_INDEX(String, usize);

    relation E_LOCALDB_SCOPE(String, String);

    relation E_MAPSYM_SYMBOL(String, PCodeHighSymbol);

    relation E_OP_ADDR(PCodeInstruction, String);
    relation A_OP_CODE(PCodeInstruction, String);
    relation E_OP_IOP(PCodeInstruction, String);
    relation A_OP_INDEX(PCodeInstruction, usize);
    relation E_OP_INPUT(PCodeInstruction, String);
    relation E_OP_OUTPUT(PCodeInstruction, String);
    relation A_OP_OPREF(PCodeInstruction, usize);
    relation E_OP_SEQNUM(PCodeInstruction, String);
    relation E_OP_SPACEID(PCodeInstruction, String);

    relation A_PROTOTYPE_CONSTRUCTOR(PCodeHighPrototype, String);
    relation A_PROTOTYPE_DESTRUCTOR(PCodeHighPrototype, String);
    relation A_PROTOTYPE_DOTDOTDOT(PCodeHighPrototype, String);
    relation A_PROTOTYPE_INLINE(PCodeHighPrototype, String);
    relation A_PROTOTYPE_MODEL(PCodeHighPrototype, PCodeGenericCallingConvention);
    relation E_PROTOTYPE_RETURNSYM(PCodeHighPrototype, String);   

    relation E_RANGELIST_RANGE(String, String);
    relation A_RANGE_FIRST(String, String);
    relation A_RANGE_LAST(String, String);

    relation E_RETURNSYM_VOID(String, String);
    relation E_RETURNSYM_TYPE(String, String);
    relation E_RETURNSYM_TYPEREF(String, String);

    relation E_SCOPE_SYMBOLLIST(String, String);

    relation A_SEQNUM_OFFSET(String, String);
    relation A_SEQNUM_OFFSET_N(String, usize);
    relation A_SEQNUM_OFFSET_HEX(String, String);
    relation A_SEQNUM_OFFSET_UNIQ(String, usize);
    relation A_SEQNUM_UNIQ(String, usize);

    relation A_SPACEID_NAME(String, String);

    relation E_STATEMENT_FIELD(String, String);
    relation E_STATEMENT_FUNCNAME(String, String);
    relation E_STATEMENT_OP(String, PCodeInstruction);
    relation A_STATEMENT_OPREF(String, usize);
    relation E_STATEMENT_VARIABLE(String, String);

    relation E_SYMBOLLIST_MAPSYM(String, String);

    relation A_SYMBOL_CAT(PCodeHighSymbol, usize);
    relation A_SYMBOL_INDEX(PCodeHighSymbol, usize);
    relation A_SYMBOL_NAME(PCodeHighSymbol, String);
    relation A_SYMBOL_ID(PCodeHighSymbol, usize);
    relation E_SYMBOL_TYPE(PCodeHighSymbol, String);
    relation E_SYMBOL_TYPEREF(PCodeHighSymbol, String);

    relation A_TYPE_NAME(PCodeType, String);
    relation A_TYPE_METATYPE(PCodeType, PCodeType);
    relation A_TYPE_SIZE(PCodeType, usize);
    relation E_TYPE_TYPEREF(PCodeType, String);
    relation A_TYPEREF_NAME(String, String);

    relation E_VARDECL_VARIABLE(String, String);
    relation A_VARIABLE_OPREF(String, usize);
    relation A_VARIABLE_VARREF(String, usize);
    relation A_VARIABLE_XMLCONTENT(String, String);
    relation E_VARNODES_ADDR(String, String);


    // --- DERIVED LOGIC RULES ---
    location_hfunc(a.clone(), fn_id.clone()) <-- 
        LOCATION_FUNC(a, fn_id);

    op_hfunc(op.clone(), fn_id.clone()) <-- 
        E_OP_ADDR(op, a), 
        E_BLOCK_OP(bb, op), 
        BB_HFUNCX(bb, fn_id), 
        E_DOC_FUNCTION(fn_id, _);
        
    op_hfunc(op.clone(), fn_id.clone()) <-- 
        E_OP_IOP(op, a), 
        E_BLOCK_OP(bb, op), 
        BB_HFUNCX(bb, fn_id), 
        E_DOC_FUNCTION(fn_id, _);


    bb_hfunc(bb.clone(), fn_id.clone()) <-- 
        E_OP_ADDR(op, a),
     	E_BLOCK_OP(bb, op), 
     	BB_HFUNCX(bb, fn_id), 
     	E_DOC_FUNCTION(fn_id, _);
     	
    bb_hfunc(bb.clone(), fn_id.clone()) <-- 
        E_OP_IOP(op, a), 
        E_BLOCK_OP(bb, op), 
        BB_HFUNCX(bb, fn_id), 
        E_DOC_FUNCTION(fn_id, _);


    location_hfunc(a.clone(), fn_id.clone()) <-- 
        E_OP_ADDR(op, a), 
        E_BLOCK_OP(bb, op), 
        BB_HFUNCX(bb, fn_id), 
        E_DOC_FUNCTION(fn_id, _);
        
    location_hfunc(a.clone(), fn_id.clone()) <-- 
        E_OP_IOP(op, a), 
        E_BLOCK_OP(bb, op), 
        BB_HFUNCX(bb, fn_id), 
        E_DOC_FUNCTION(fn_id, _);


    OFFSET_INDEXX(num.clone(), n) <-- 
        LOCATION_NUM(off, num), 
        LOCATION_UNIQ(off, n);


    VNODE_NAMEX(id.clone(), format!("vn{}", r)) <-- 
        A_ADDR_REF(a, r), 
        location_hfunc(a, fn_id), 
        let id = format!("{}:{}", fn_id, r);
        
    vnode_id(id.clone(), a.clone()) <-- 
        A_ADDR_REF(a, r), 
        location_hfunc(a, fn_id), 
        let id = format!("{}:{}", fn_id, r);

    VNODE_SPACEX(id.clone(), "const".to_string()) <-- 
        E_OP_IOP(op, id), 
        A_IOP_VALUE(id, num);
        
    VNODE_ADDRESSX(id.clone(), num.clone()) <-- 
        E_OP_IOP(op, id), 
        A_IOP_VALUE(id, num);
        
    VNODE_NAMEX(id.clone(), id.clone()) <-- 
        E_OP_IOP(op, id), 
        A_IOP_VALUE(id, num);

    vnode_id(id.clone(), id.clone()) <-- 
        E_OP_IOP(op, id), 
        A_IOP_VALUE(id, num);

    VNODE_SPACEX(id.clone(), "const".to_string()) <-- 
        E_OP_SPACEID(op, id), 
        A_SPACEID_NAME(id, num);
        
    VNODE_ADDRESSX(id.clone(), num.clone()) <-- 
        E_OP_SPACEID(op, id), 
        A_SPACEID_NAME(id, num);
        
    VNODE_NAMEX(id.clone(), id.clone()) <-- 
        E_OP_SPACEID(op, id), 
        A_SPACEID_NAME(id, num);
        
    vnode_id(id.clone(), id.clone()) <-- 
        E_OP_SPACEID(op, id), 
        A_SPACEID_NAME(id, num);
        
    VNODE_ADDRESSX(id.clone(), num.clone()) <--
        vnode_id(id, a), 
        A_ADDR_OFFSET(a, off), 
        LOCATION_NUM(off, num);
        
    VNODE_SPACEX(id.clone(), sp.clone()) <--
        vnode_id(id, a), 
        A_ADDR_SPACE(a, sp);
        
    VNODE_OFFSETX(id.clone(), off.clone()) <--
        VNODE_ADDRESSX(id, a), 
        LOCATION_HEX(a, off);
        
    VNODE_OFFSET_NX(id.clone(), n.clone()) <--
        VNODE_ADDRESSX(id, a), 
        LOCATION_NUM(a, n);
        
    VNODE_PC_ADDRESSX(id.clone(), off.clone()) <--
        vnode_id(id, a), 
        A_ADDR_REF(a, aref), 
    	A_VARIABLE_VARREF(v, aref),
    	A_VARIABLE_OPREF(v, ref_val), 
    	A_SEQNUM_UNIQ(sq, ref_val), 
    	A_SEQNUM_OFFSET(sq, off);
    	
    VNODE_PC_ADDRESSX(id.clone(), off.clone()) <--
        vnode_id(id, a), 
        E_OP_OUTPUT(op, a), 
        E_OP_SEQNUM(op, sq), 
        A_SEQNUM_OFFSET(sq, off);
        
    VNODE_SIZEX(id.clone(), *sz) <--
        vnode_id(id, a), 
        A_ADDR_SIZE(a, sz);
        
    VNODE_SIZEX(id.clone(), *sz) <--
        vnode_id(id, a), 
        A_ADDR_REF(a, r), 
        A_HIGH_REPREF(hv, r), 
        E_HIGH_TYPE(hv, t), 
        A_TYPE_SIZE(t, sz);
        
    VNODE_HFUNCX(id.clone(), fn_id.clone()) <--
        vnode_id(id, a), l
        ocation_hfunc(a, fn_id);
        
    VNODE_HVARX(id.clone(), hv.clone()) <--
        vnode_id(id, a), 
        E_HIGH_ADDR(hv, a);


    PCODE_MNEMONICX(op.clone(), mn.clone()) <--
        A_OP_CODE(op, n), 
        MNEMONICS(n, mn);
        
    PCODE_OPCODEX(op.clone(), n.clone()) <--
        A_OP_CODE(op, n);
        
    PCODE_INPUTX(op.clone(), *n, id.clone()) <--
        E_OP_INPUT(op, addr), 
        vnode_id(id, addr), 
        A_INPUT_INDEX(addr, n);
        
    PCODE_OUTPUTX(op.clone(), id.clone()) <--
        E_OP_OUTPUT(op, addr), 
        vnode_id(id, addr);
        
    PCODE_TARGETX(op.clone(), addr.clone()) <--
        E_OP_SEQNUM(op, sq), 
        A_SEQNUM_OFFSET(sq, addr);
        
    PCODE_PARENTX(op.clone(), p.clone()) <--
        A_OP_CODE(op, _), 
        E_BLOCK_OP(p, op);
        
    PCODE_NEXTX(op.clone(), nxt.clone()) <--
        E_OP_SEQNUM(op, opsq), 
        E_BLOCK_OP(block, op), 
        E_BLOCK_OP(block, nxt),
        A_OP_INDEX(op, opn), 
        A_OP_INDEX(nxt, nxtn), 
        if *nxtn == *opn + 1;
        
    pcode_id(op.clone(), format!("{}:{}", addr, ref_val)) <--
        E_OP_SEQNUM(op, sq), 
        A_SEQNUM_OFFSET(sq, addr), 
        A_OP_INDEX(op, ref_val);
        
    PCODE_INDEXX(op.clone(), *idx) <--
        A_OP_INDEX(op, idx);


    SYMBOL_NAMEX(hs.clone(), name.clone()) <--
        A_SYMBOL_NAME(hs, name);
        
    SYMBOL_HVARX(hs.clone(), hv.clone()) <--
        A_HIGH_SYMREF(hv, r), 
        A_SYMBOL_ID(hs, r), 
        hvar_hfunc(hv, fn_id), 
        SYMBOL_HFUNCX(hs, fn_id);
        
    SYMBOL_HFUNCX(hs.clone(), fn_id.clone()) <--
        E_DOC_FUNCTION(fn_id, f), 
        E_FUNCTION_LOCALDB(f, db), 
        E_LOCALDB_SCOPE(db, scope),
        E_SCOPE_SYMBOLLIST(scope, list), 
        E_SYMBOLLIST_MAPSYM(list, map), 
        E_MAPSYM_SYMBOL(map, hs);


    hvar_hfunc(hv.clone(), fn_id.clone()) <--
        E_DOC_FUNCTION(fn_id, f), 
        E_FUNCTION_HIGHLIST(f, list), 
        E_HIGHLIST_HIGH(list, hv);
        
    HVAR_NAMEX(hv.clone(), name.clone()) <--
        SYMBOL_HVARX(sym, hv), 
        A_SYMBOL_NAME(sym, name);
        
    HVAR_NAMEX(hv.clone(), name.clone()) <--
        varnode_hvar(v, hv), 
        A_VARIABLE_XMLCONTENT(v, name);
        
    HVAR_NAMEX(hv.clone(), format!("{}.{}", prefix, suffix)) <--
        varnode_hvar(v, hv), 
        A_VARIABLE_XMLCONTENT(v, prefix), 
        VARIABLE_FIELD(v, f), 
        A_FIELD_XMLCONTENT(f, suffix);
        
    HVAR_NAMEX(hv.clone(), format!("{}:{}:{}", fn_id, space, off)) <--
        hvar_hfunc(hv, fn_id), 
        A_HIGH_REPREF(hv, r), 
        A_ADDR_REF(a, r),
        A_ADDR_OFFSET(a, off), 
        A_ADDR_SPACE(a, space), 
        location_hfunc(a, fn_id);
        
    HVAR_NAMEX(hv.clone(), format!("{}:{}", cls, off)) <--
        A_HIGH_CLASS(hv, cls), 
        E_HIGH_ADDR(hv, addr), 
        A_ADDR_OFFSET(addr, off);
        
    HVAR_REPRESENTATIVEX(hv.clone(), id.clone()) <--
        vnode_id(id, a), 
        A_ADDR_REF(a, r), 
        A_HIGH_REPREF(hv, r);
        
    HVAR_TYPEX(hv.clone(), t.clone()) <--
        E_HIGH_TYPE(hv, t);
        
    HVAR_TYPEX(hv.clone(), r.clone()) <--
        E_HIGH_TYPEREF(hv, r);


    BB_FIRSTX(bb.clone(), op.clone()) <--
        E_BLOCK_OP(bb, op), 
        A_OP_INDEX(op, n), 
        if *n == 0;
        
    BB_EDGE(b0.clone(), b1.clone()) <--
        A_BLOCKEDGE_INDEX(be, to), 
        E_BLOCKEDGE_EDGE(be, e), 
        A_EDGE_END(e, from),
        _BLOCK_INDEX(b0, from), 
        A_BLOCK_INDEX(b1, to);
        
    BB_HFUNCX(bb.clone(), fn_id.clone()) <--
        E_DOC_FUNCTION(fn_id, f), 
        E_FUNCTION_BLOCK(f, bb);
        
    BB_HFUNCX(bb.clone(), fn_id.clone()) <--
        E_DOC_FUNCTION(fn_id, f), 
        E_FUNCTION_AST(f, ast), 
        E_AST_BLOCK(ast, bb);
        
    BB_HFUNCX(bb.clone(), fn_id.clone()) <--
        BB_HFUNCX(bbf, fn_id), 
        E_BLOCK_BLOCK(bbf, bb);


    HFUNC_EPX(fn_id.clone(), off.clone()) <--
        E_DOC_FUNCTION(fn_id, f), 
        E_FUNCTION_ADDR(f, addr), 
        A_ADDR_OFFSET(addr, off);
        
    HFUNC_LOCAL_EPX(off.clone(), off.clone()) <--
        E_FUNCTION_ADDR(_, addr), 
        A_ADDR_OFFSET(addr, off);
        
    HFUNC_FUNCX(fn_id.clone(), fn_id.clone()) <--
        E_DOC_FUNCTION(fn_id, _);
        
    HFUNC_NAMEX(fn_id.clone(), name.clone()) <--
        E_DOC_FUNCTION(fn_id, f), 
        A_FUNCTION_NAME(f, name);
        
    HFUNC_ISEXTX(fn_id.clone()) <--
        E_DOC_FUNCTION(fn_id, f), 
        HFUNC_FUNCX(f, fx), 
        FUNC_ISEXT(fx);
        
    HFUNC_PROTOX(fn_id.clone(), p.clone()) <--
        E_DOC_FUNCTION(fn_id, f), 
        E_FUNCTION_FUNCPROTO(f, p);


    PROTO_CALLING_CONVENTIONX(proto.clone(), cc.clone()) <--
        A_PROTOTYPE_MODEL(proto, cc);
        
    PROTO_HAS_THISX(proto.clone()) <--
        A_PROTOTYPE_MODEL(proto, &"__thiscall".to_string());
        
    PROTO_IS_CONSTRUCTORX(proto.clone()) <--
        A_PROTOTYPE_CONSTRUCTOR(proto, &"true".to_string());
        
    PROTO_IS_DESTRUCTORX(proto.clone()) <--
        A_PROTOTYPE_DESTRUCTOR(proto, &"true".to_string());
        
    PROTO_IS_INLINEX(proto.clone()) <--
        A_PROTOTYPE_INLINE(proto, &"true".to_string());
    PROTO_IS_VARARGX(proto.clone()) <--
        A_PROTOTYPE_DOTDOTDOT(proto, &"true".to_string());
        
    PROTO_IS_VOIDX(proto.clone()) <--
        E_PROTOTYPE_RETURNSYM(proto, ret), E_RETURNSYM_VOID(ret, _);
        
    PROTO_PARAMETERX(proto.clone(), *n, p.clone()) <--
        SYMBOL_HFUNCX(p, fn_id), 
        A_SYMBOL_CAT(p, &0), A
        _SYMBOL_INDEX(p, n),
        E_DOC_FUNCTION(fn_id, f), 
        E_FUNCTION_FUNCPROTO(f, proto);
        
    PROTO_PARAMETER_COUNTX(proto.clone(), mx + 1) <--
        agg mx = ascent::aggregators::max(n) <-- PROTO_PARAMETERX(proto, n, _);
        
    PROTO_PARAMETER_DATATYPEX(p.clone(), t.clone()) <--
        PROTO_PARAMETERX(_, , p), E_SYMBOL_TYPE(p, t);
        
    PROTO_PARAMETER_DATATYPEX(p.clone(), r.clone()) <--
        PROTO_PARAMETERX(, _, p), E_SYMBOL_TYPEREF(p, r);
        
    PROTO_RETTYPEX(proto.clone(), t.clone()) <--
        E_PROTOTYPE_RETURNSYM(proto, sym), E_RETURNSYM_TYPE(sym, t);
        
    PROTO_RETTYPEX(proto.clone(), r.clone()) <--
        E_PROTOTYPE_RETURNSYM(proto, sym), E_RETURNSYM_TYPEREF(sym, r);


    varnode_hfunc(v.clone(), fn_id.clone()) <--
        E_BLOCK_VARIABLE(bb, v), 
        BB_HFUNCX(bb, fn_id);
        
    varnode_hfunc(v.clone(), fn_id.clone()) <--
        E_STATEMENT_VARIABLE(st, v), 
        E_BLOCK_STATEMENT(bb, st), 
        BB_HFUNCX(bb, fn_id);
        
    varnode_hfunc(v.clone(), fn_id.clone()) <--
        E_VARDECL_VARIABLE(decl, v), 
        E_FUNCTION_VARDECL(f, decl), 
        E_DOC_FUNCTION(fn_id, f);
        
    varnode_hfunc(v.clone(), fn_id.clone()) <--
        E_VARDECL_VARIABLE(decl, v), 
        E_FUNCPROTO_VARDECL(proto, decl),
        E_FUNCTION_FUNCPROTO(f, proto), 
        E_DOC_FUNCTION(fn_id, f);
        
    varnode_hfunc(v.clone(), fn_id.clone()) <--
        E_DOC_FUNCTION(fn_id, f), 
        E_FUNCTION_AST(f, ast), 
        E_AST_VARNODES(ast, v);
        
    varnode_hfunc(a.clone(), fn_id.clone()) <--
        E_OP_INPUT(op, a), 
        E_OP_SEQNUM(op, sq), 
        location_hfunc(sq, fn_id);
        
    varnode_hfunc(a.clone(), fn_id.clone()) <--
        E_OP_OUTPUT(op, a), 
        E_OP_SEQNUM(op, sq), 
        location_hfunc(sq, fn_id);
        
    varnode_hvar(v.clone(), hv.clone()) <--
        E_HIGH_ADDR(hv, addr), 
        A_ADDR_REF(addr, r), 
        A_VARIABLE_VARREF(v, r),
        location_hfunc(addr, fn_id), 
        varnode_hfunc(v, fn_id);
        
    varnode_hvar(v.clone(), hv.clone()) <--
        E_HIGH_ADDR(hv, addr), 
        A_HIGH_REPREF(hv, r), 
        A_VARIABLE_VARREF(v, r),
        location_hfunc(addr, fn_id), 
        varnode_hfunc(v, fn_id);
        
    varnode_hvar(v.clone(), hv.clone()) <--
        A_VARIABLE_XMLCONTENT(v, _xml), 
        A_VARIABLE_OPREF(v, ref_val),
        A_SEQNUM_UNIQ(sq, ref_val), 
        E_OP_SEQNUM(op, sq), 
        E_OP_ADDR(op, x),
        A_ADDR_REF(x, xref), 
        A_HIGH_REPREF(hv, xref);
}

// ==========================================
// 3. FACT IO UTILITY TRAITS
// ==========================================
trait WriteTsv {
    fn write_tsv(&self, writer: &mut BufWriter) -> std::io::Result<()>;
}

impl WriteTsv for () {
    fn write_tsv(&self, writer: &mut BufWriter) -> 
        td::io::Result<()> { 
            writeln!(writer) 
        }
}
			
impl<T: std::fmt::Display> WriteTsv for (T,) {
    fn write_tsv(&self, writer: &mut BufWriter) -> 
        std::io::Result<()> { 
	    writeln!(writer, "{}", self.0) 
        }
}
    
impl<T1: std::fmt::Display, T2: std::fmt::Display> WriteTsv for (T1, T2) {
    fn write_tsv(&self, writer: &mut BufWriter) -> s
        td::io::Result<()> { 
            writeln!(writer, "{}\t{}", self.0, self.1) 
        }
}
    
impl<T1: std::fmt::Display, T2: std::fmt::Display, T3: std::fmt::Display> WriteTsv for (T1, T2, T3) {
    fn write_tsv(&self, writer: &mut BufWriter) -> 
        std::io::Result<()> { 
            writeln!(writer, "{}\t{}\t{}", self.0, self.1, self.2) 
        }
}
    
fn export_relation<T: WriteTsv>(data: &[T], filename: &str) -> 
std::io::Result<()> {
    let base_dir = "./export";
    let path = Path::new(base_dir).join(filename);
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    for row in data {
        row.write_tsv(&mut writer)?;
    }
    Ok(())
}
    
// ==========================================
// 4. MAIN PROGRAM RUNTIME LOOP
// ==========================================
fn main() {
    let mut prog = AscentProgram::default();
    println!("Starting Ascent PCode Engine Evaluation loop...");
    prog.run();
    println!("Evaluation complete. Serializing data to TSV targets...");

    // Export output sequences mirroring Souffle target allocationslet _ = export_relation(&prog.tmp, "TMP.facts");
    let _ = export_relation(&prog.OFFSET_INDEXX, "OFFSET_INDEX.facts");
    let _ = export_relation(&prog.VNODE_SPACEX, "VNODE_SPACE.facts");
    let _ = export_relation(&prog.VNODE_PC_ADDRESSX, "VNODE_PC_ADDRESS.facts");
    let _ = export_relation(&prog.VNODE_ADDRESSX, "VNODE_ADDRESS.facts");
    let _ = export_relation(&prog.VNODE_OFFSETX, "VNODE_OFFSET.facts");
    let _ = export_relation(&prog.VNODE_OFFSET_NX, "VNODE_OFFSET_N.facts");
    let _ = export_relation(&prog.VNODE_NAMEX, "VNODE_NAME.facts");
    let _ = export_relation(&prog.VNODE_SIZEX, "VNODE_SIZE.facts");
    let _ = export_relation(&prog.VNODE_HFUNCX, "VNODE_HFUNC.facts");
    let _ = export_relation(&prog.VNODE_HVARX, "VNODE_HVAR.facts");
    let _ = export_relation(&prog.PCODE_INDEXX, "PCODE_INDEX.facts");
    let _ = export_relation(&prog.PCODE_INPUTX, "PCODE_INPUT.facts");
    let _ = export_relation(&prog.PCODE_OUTPUTX, "PCODE_OUTPUT.facts");
    let _ = export_relation(&prog.PCODE_MNEMONICX, "PCODE_MNEMONIC.facts");
    let _ = export_relation(&prog.PCODE_NEXTX, "PCODE_NEXT.facts");
    let _ = export_relation(&prog.PCODE_OPCODEX, "PCODE_OPCODE.facts");
    let _ = export_relation(&prog.PCODE_TARGETX, "PCODE_TARGET.facts");
    let _ = export_relation(&prog.PCODE_PARENTX, "PCODE_PARENT.facts");
    let _ = export_relation(&prog.SYMBOL_NAMEX, "SYMBOL_NAME.facts");
    let _ = export_relation(&prog.SYMBOL_HFUNCX, "SYMBOL_HFUNC.facts");
    let _ = export_relation(&prog.SYMBOL_HVARX, "SYMBOL_HVAR.facts");
    let _ = export_relation(&prog.hvar_hfunc, "HVAR_HFUNC.facts");
    let _ = export_relation(&prog.HVAR_NAMEX, "HVAR_NAME.facts");
    let _ = export_relation(&prog.HVAR_REPRESENTATIVEX, "HVAR_REPRESENTATIVE.facts");
    let _ = export_relation(&prog.HFUNC_EPX, "HFUNC_EP.facts");
    let _ = export_relation(&prog.HFUNC_FUNCX, "HFUNC_FUNC.facts");
    let _ = export_relation(&prog.HFUNC_NAMEX, "HFUNC_NAME.facts");
    let _ = export_relation(&prog.HFUNC_ISEXTX, "HFUNC_ISEXT.facts");
    let _ = export_relation(&prog.HFUNC_LOCAL_EPX, "HFUNC_LOCAL_EP.facts");
    let _ = export_relation(&prog.HFUNC_PROTOX, "HFUNC_PROTO.facts");
    let _ = export_relation(&prog.BB_FIRSTX, "BB_FIRST.facts");
    let _ = export_relation(&prog.BB_HFUNCX, "BB_HFUNC.facts");
    let _ = export_relation(&prog.pcode_id, "PCODE_ID.facts");
    let _ = export_relation(&prog.vnode_id, "VNODE_ID.facts");
    let _ = export_relation(&prog.location_hfunc, "LOCATION_HFUNC.facts");
    let _ = export_relation(&prog.varnode_hfunc, "VARNODE_HFUNC.facts");
    let _ = export_relation(&prog.varnode_hvar, "VARNODE_HVAR.facts");
    println!("All data successfully written out to the export directory!");
}
