import angr
import sys
binary = './angr_2'

good = (0x401245,0x4013C7)
bad = (0x4013B0)

def is_good(state):
    return b'Good Job' in state.posix.dumps(1)
def is_bad(state):
    return b'Try again' in state.posix.dumps(1)
    
p = angr.Project(binary)
state = p.factory.entry_state()
simulation = p.factory.simgr(state)
simulation.explore(find=is_good, avoid=is_bad)
if simulation.found:
    solution_state = simulation.found[0]
    for i in range(3):
        print (solution_state.posix.dumps(i))
else:
    raise Exception("Could not find the solution")


