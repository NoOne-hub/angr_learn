import angr
import sys
binary = './angr_0'
good = 0x401329

p = angr.Project(binary)
state = p.factory.entry_state()
simulation = p.factory.simgr(state)
simulation.explore(find=good)
if simulation.found:
    solution_state = simulation.found[0]
    for i in range(3):
        print (solution_state.posix.dumps(i))
else:
    raise Exception("Could not find the solution")


