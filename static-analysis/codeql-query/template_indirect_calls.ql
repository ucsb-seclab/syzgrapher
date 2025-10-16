
from VariableCall vc, Struct st, PointerFieldAccess pfa, Field f
where 
  (
    isInSyscall(vc)
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
