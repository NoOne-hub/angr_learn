import angr
import sys
binary = './angr_1'

good = (0x4012D0)
bad = (0x40127B)

p = angr.Project(binary)
state = p.factory.entry_state()
simulation = p.factory.simgr(state)
simulation.explore(find=good, avoid=bad)
if simulation.found:
    solution_state = simulation.found[0]
    for i in range(3):
        print (solution_state.posix.dumps(i))
else:
    raise Exception("Could not find the solution")


