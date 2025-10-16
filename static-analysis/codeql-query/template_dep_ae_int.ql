
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
      bs.getStmt(0) = es
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
      rs.getExpr() = ume) // return - EXX
  )
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

predicate aeToPfa(AssignExpr ae, PointerFieldAccess pfa) {
  ae.getLValue() = pfa
  or
  exists(VariableAccess va, AssignExpr ae2, DataFlow::Node source, DataFlow::Node sink |
    ae.getLValue() = va
    and
    source.asExpr() = va
    and
    sink.asExpr() = ae2.getRValue()
    and
    ae2.getLValue() = pfa
    and
    DataFlow::localFlow(source, sink)
  )
}

predicate matchLeftSides(NEExpr nee, AssignExpr ae, PointerFieldAccess pfa1) {
  exists(PointerFieldAccess pfa2 |
    pfaToNee(pfa1, nee)
    and
    aeToPfa(ae, pfa2)
    and
    pfa1.getTarget() = pfa2.getTarget()
  ) // could be extended to also match the value
}

predicate matchLeftSidesLight(NEExpr nee, AssignExpr ae, PointerFieldAccess pfa1) {
  exists(PointerFieldAccess pfa2 |
    nee.getLeftOperand() = pfa2
    and
    ae.getLValue() = pfa1
    and
    pfa1.getTarget() = pfa2.getTarget()
    )
}

from Literal l, Literal l2,
     IfStmt ifs,
     NEExpr nee,
     AssignExpr ae,
     Function f1,
     Function f2,
     PointerFieldAccess pfa,
     Struct s
   where 
       (
        ( 
          f1.calls*(ae.getEnclosingFunction())
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
            f2.calls*(ifs.getEnclosingFunction())
            and
            isValidEntrypoint(f2)
          )
        )
        and
        isErrorPathGuard(ifs)
        and
        (
          ae.getRValue() = l2
        )
        and
        l.getValue() = l2.getValue()
        and
        matchLeftSidesLight(nee, ae, pfa)   
        and
        f2.getName() != f1.getName()
        and
        s.getAField() = pfa.getTarget()
       )
select ifs.getLocation(), f2.getName() + " | " + f1.getName() + " | " + l2.getValue() + " | " + (s.getName() + ":" + pfa.getTarget().getName()) + " | " + ifs.getLocation().getFile().toString() + " | " + ifs.getLocation().getStartLine().toString() + " | " + ae.getLocation().getFile().toString() + " | " + ae.getLocation().getStartLine().toString()
