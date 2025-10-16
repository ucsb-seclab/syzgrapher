
predicate isErrorPathGuard(IfStmt ifs) {
  ifs.getEnclosingFunction().getType().getName() != "void"
  and
  (
    exists(BreakStmt bs | ifs.getThen() = bs and bs.getBasicBlock().length() = 1) // break; not sure we want to check for length here
    or
    exists(GotoStmt gs | ifs.getThen() = gs) // goto err
    or
    exists(BlockStmt bs, ExprStmt es, AssignExpr ae, VariableAccess va, UnaryMinusExpr ume |
      ifs.getThen() = bs
      and
      bs.getStmt(0) = es // TODO we could generalize this to any statement in the block
      and
      es.getExpr() = ae
      and
      ae.getLValue() = va
      and
      ae.getRValue() = ume
    ) // err = - EXXX
    or
    exists(ReturnStmt rs, UnaryMinusExpr ume | 
      ifs.getThen() = rs
      and
      rs.getExpr() = ume
    ) // return - EXX
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
    // "__kasan_slab_free", "kmem_cache_free",
  ]
  or
  f.getName().matches("%kfree%")
}

predicate myCalls(Function f1, Function f2) {
  f1.calls(f2)
  and
  not memoryOperation(f2)
}

predicate pfaToNee(PointerFieldAccess pfa, NEExpr nee) {
  nee.getLeftOperand() = pfa 
  or
  exists(VariableAccess va, DataFlow::Node source, DataFlow::Node sink |
    source.asExpr() = pfa
    and
    sink.asExpr() = va
    and
    nee.getLeftOperand() = va
    and
    DataFlow::localFlow(source, sink)
  )
}

predicate fcToPfaHelper(FunctionCall fc, int i, PointerFieldAccess pfa) {
  i in [0, 1]
  and
  // df from arg to pfa
  exists(Parameter p, AssignExpr ae, DataFlow::Node source, DataFlow::Node sink |
    source.asParameter() = p
    and
    fc.getTarget().getParameter(i) = p
    and
    sink.asExpr() = ae.getRValue()
    and
    ae.getLValue() = pfa
    and
    DataFlow::localFlow(source, sink)  
  )
}

predicate fcToPfa(FunctionCall fc, Literal l, PointerFieldAccess pfa) {
  pfa.getEnclosingFunction() = fc.getTarget()
  and  
  (
    (
      fc.getArgument(0) = l
      and
      fcToPfaHelper(fc, 0, pfa)
    )
    or
    (
      fc.getArgument(1) = l
      and
      fcToPfaHelper(fc, 1, pfa)
    )
  )
  
}

predicate matchleftSides(NEExpr nee, FunctionCall fc, Literal l2, PointerFieldAccess pfa1) {
  exists(PointerFieldAccess pfa2 |
    pfaToNee(pfa1, nee)
    and
    fcToPfa(fc, l2, pfa2)
    and
    pfa1.getTarget() = pfa2.getTarget()
  ) // could be extended to also match the value
}

predicate matchLeftSidesLight(NEExpr nee, FunctionCall fc, PointerFieldAccess pfa1) {
  pfa1.getEnclosingFunction() = fc.getTarget()
  and
  exists(PointerFieldAccess pfa2, AssignExpr ae |
    nee.getLeftOperand() = pfa2
    and
    ae.getEnclosingFunction() = fc.getTarget()
    and
    ae.getLValue() = pfa1
    and
    pfa1.getTarget() = pfa2.getTarget()
    )
}

from FunctionCall fc,
    Literal l,
    Literal l2,
    IfStmt ifs,
    NEExpr nee,
    Function f1,
    Function f2,
    PointerFieldAccess pfa,
    Struct s
  where 
      (
      ( 
        myCalls*(f1, fc.getEnclosingFunction())
        and
        isValidEntrypoint(f1)
      )
      and
      nee.getParent*() = ifs
      and
      nee.getRightOperand() = l
      and
      (
        (
          myCalls*(f2, ifs.getEnclosingFunction())
          and
          isValidEntrypoint(f2)
        )
      )
      and
      isErrorPathGuard(ifs)
      and
      (
        fc.getAnArgument() = l2
        and
        fc.getNumberOfArguments() = [2]
      )
      and
      l.getValue() = l2.getValue()
      and
      matchLeftSidesLight(nee, fc, pfa)
      and
      f2.getName() != f1.getName()
      and
      s.getAField() = pfa.getTarget()
      )
select ifs.getLocation(), f2.getName() + " | " + f1.getName() + " | " + l2.getValue() + " | " + (s.getName() + ":" + pfa.getTarget().getName()) + " | " + ifs.getLocation().getFile().toString() + " | " + ifs.getLocation().getStartLine().toString() + " | " + fc.getLocation().getFile().toString() + " | " + fc.getLocation().getStartLine().toString()
