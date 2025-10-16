    and
    f.calls*(s.getEnclosingFunction())
  )
  and
  relevantStatement2Helper(s, a)
}


int getDir(SwitchCase sc) {
  result = sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(Literal).getValue().toInt()
  or
  result = sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue().toInt() +
  sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue().toInt()
}

int getType(SwitchCase sc) {
  result = sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue().toInt()
}

int getNR(SwitchCase sc) {
  result = sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue().toInt()
}

predicate relevantStatement2Helper(Stmt s, ValidOpts a) {
  a.checkCase(s.(SwitchCase))
  or
  (
    not s instanceof SwitchCase
    and
    exists(SwitchStmt sws, BlockStmt bs |
      sws.getStmt() = bs 
      and
      bs.getAStmt() = s
      and
      relevantStatement2Helper(bs.getStmt(bs.getIndexOfStmt(s)-1), a)
    )
  )
}
 
predicate vcIndirectReachableFromStmt(Stmt s, VariableCall vc) {
  not s.getAChild*() = vc.getEnclosingStmt*()
  and
  exists(FunctionCall fc2 |
    s.getAChild*() = fc2.getEnclosingStmt*()
    and
    myCalls*(fc2.getTarget(), vc.getEnclosingFunction())
  )
}

predicate vcReachableFromStmt(Stmt s, VariableCall vc) {
  s.getAChild*() = vc.getEnclosingStmt*()
  or
  vcIndirectReachableFromStmt(s, vc)
}

predicate vcReachableFromRelevantStatement(VariableCall vc, ValidOpts a) {
  exists(Stmt s |
    relevantStatement(s, a)
    and
    vcReachableFromStmt(s, vc)
  )
}

predicate memoryOperation(Function f){
  f.getName() = [
    "kmalloc", "kzalloc", "kcalloc", "kvmalloc_node",
    "kmalloc_node", "vmalloc", "vmalloc_node", "__kmalloc",
    "__vmalloc_node", "kmalloc_array", "__vmalloc_node_range",
    "__kmalloc_node", "krealloc_array", "kzalloc_node",
    "krealloc", "vmalloc_huge", "vzalloc", "vmalloc_user",
    "vzalloc_node", "vmalloc_32", "vmalloc_32_user",
    "kcalloc_node", "kmalloc_array_node", "__vmalloc",
    "kvzalloc", "kvmalloc", "kvmalloc_array", "kvcalloc",
    "kvzalloc_node", "kvcalloc_node",
    "kmem_cache_alloc", "kmem_cache_alloc_node",
    "kmem_cache_zalloc", "allocate_mm",
    "malloc", "calloc","alloc_pages"
  ]
  or
  f.getName().matches("%alloc%")
  or
  f.getName() = [
    "kfree", "kvfree", "vfree", "kfree_sensitive",
    "kmem_cache_free","kfree_const","kvfree_call_rcu",
    "kfree_skb","free_pages"
    // "__kasan_slab_free"
  ]
  or
  f.getName().matches("%kfree%")
}

predicate myCalls(Function f1, Function f2) {
  f1.calls(f2)
  and
  not memoryOperation(f2)
}


from VariableCall vc, Struct st, PointerFieldAccess pfa, Field f, ValidOpts a
where 
  (
    vcReachableFromRelevantStatement(vc, a)
    and 
    vc.getExpr() = pfa
    and
    pfa.getTarget() = f
    and
    st.getAField() = f
    and
    st.getName() = ["proto_ops", "sock", "proto", "file_operations"]
  )
select vc.getLocation(), st.getName() + " | " + f.getByteOffset() + " | " + f.getName()